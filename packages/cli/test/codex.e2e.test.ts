import fs from "node:fs";
import path from "node:path";
import type { SecretMeta } from "@agent-vault/core";
import { connect } from "@agent-vault/daemon";
import { getPaths, ipcEndpoint } from "@agent-vault/platform";
import { afterAll, describe, expect, test } from "vitest";
import { fakes } from "../../detect/test/fixtures/fake-keys.js";
import { alive, makeSandbox, type Sandbox } from "./harness.js";

// Each call starts node, and the first one in a sandbox also starts the daemon.
const TIMEOUT_MS = 60_000;

const TRUST_ACTION =
  "ACTION NEEDED: open Codex, run /hooks, select agent-vault and press t. Until then Codex skips the hook and pasted keys reach the model.";

const sandboxes: Sandbox[] = [];
const pidsSeen = new Set<number>();

function sandbox(): Sandbox {
  const sb = makeSandbox();
  sandboxes.push(sb);
  return sb;
}

afterAll(async () => {
  for (const sb of sandboxes) {
    const pid = await sb.daemonPid();
    if (pid !== null) pidsSeen.add(pid);
    await sb.stopDaemon();
    sb.remove();
  }
  for (const pid of pidsSeen) expect(alive(pid), `vaultd ${pid} is still running`).toBe(false);
}, TIMEOUT_MS);

/** Never the real `codex` (PATH holds nothing, so `codex mcp add` is "not installed"), never a real CODEX_HOME. */
function sandboxEnv(sb: Sandbox, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const empty = path.join(sb.dir, "empty-path");
  fs.mkdirSync(empty, { recursive: true });
  return { PATH: empty, Path: empty, CODEX_HOME: codexHome(sb), CLAUDE_CONFIG_DIR: "", ...extra };
}
// The daemon scrubs files under the home directory only: HOME is the sandbox dir.
const codexHome = (sb: Sandbox): string => path.join(sb.dir, ".codex");

const put = (file: string, text: string): string => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
};
const read = (file: string): string => fs.readFileSync(file, "utf8");

/** What Codex sends a UserPromptSubmit hook (spike S3, "Real stdin"). */
const s3Input = (sb: Sandbox, prompt: string): string =>
  JSON.stringify({
    session_id: "01a17b44-c1ac-7241-b013-2898e66b129d",
    turn_id: "01a17b44-fbdd-7d61-ac4b-20f6e43e66a5",
    transcript_path: rollout(sb),
    cwd: path.join(sb.dir, "proj"),
    hook_event_name: "UserPromptSubmit",
    model: "gpt-x",
    permission_mode: "default",
    prompt,
  });
const rollout = (sb: Sandbox): string =>
  path.join(codexHome(sb), "sessions", "2026", "10", "26", "rollout-01a17b44.jsonl");

const secretsOf = async (sb: Sandbox): Promise<SecretMeta[]> => {
  const client = await connect(ipcEndpoint(getPaths({ AGENT_VAULT_HOME: sb.home })));
  try {
    return await client.call<SecretMeta[]>("secret.list");
  } finally {
    client.close();
  }
};

async function secretWith(sb: Sandbox, name: string, tags: string[]): Promise<void> {
  const client = await connect(ipcEndpoint(getPaths({ AGENT_VAULT_HOME: sb.home })));
  try {
    await client.call("secret.put", {
      name,
      valueB64: Buffer.from("stand-in value, not a key").toString("base64"),
      tags,
    });
  } finally {
    client.close();
  }
}

describe("codex hook", { timeout: TIMEOUT_MS }, () => {
  const sb = sandbox();
  const PAT = fakes.githubPat();
  const OPENAI = fakes.openai();
  const hook = (event: string, stdin: string, flags: string[] = []) =>
    sb.cli(["hook", "codex", event, ...flags], { stdin, env: sandboxEnv(sb) });

  test("a prompt with 2 keys prints one {decision, reason} line and nothing else, and stores both", async () => {
    const init = await sb.cli(["init", "--keystore", "keyfile"]);
    expect(init.code, init.stderr).toBe(0);
    const pid = await sb.daemonPid();
    if (pid !== null) pidsSeen.add(pid);

    const res = await hook("prompt-submit", s3Input(sb, `use ${PAT} then ${OPENAI}`));
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout.trim().split("\n")).toHaveLength(1);
    const out = JSON.parse(res.stdout);
    expect(Object.keys(out)).toEqual(["decision", "reason"]);
    expect(out).toEqual({
      decision: "block",
      reason: expect.stringMatching(/^Stored as \S+, \S+\. Re-send using vault:\/\/\S+\.$/),
    });
    for (const text of [res.stdout, res.stderr]) {
      expect(text).not.toContain(PAT);
      expect(text).not.toContain(OPENAI);
    }

    const stored = await secretsOf(sb);
    expect(stored).toHaveLength(2);
    for (const s of stored) {
      expect(s.tags).toEqual(["exposed-locally"]);
      expect(out.reason).toContain(s.name);
    }
  });

  test("the TUI history and the rollout Codex writes afterwards are scrubbed at the next SessionStart", async () => {
    const history = path.join(codexHome(sb), "history.jsonl");
    put(history, `${JSON.stringify({ session_id: "s", ts: 1, text: `k ${PAT}` })}\n`);
    put(rollout(sb), `${JSON.stringify({ type: "response_item", content: `k ${PAT}` })}\n`);

    const res = await hook(
      "scrub",
      JSON.stringify({
        session_id: "s2",
        transcript_path: rollout(sb),
        cwd: sb.dir,
        hook_event_name: "SessionStart",
        model: "gpt-x",
        permission_mode: "default",
        source: "startup",
      }),
    );
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout).toBe("");
    for (const file of [history, rollout(sb)]) {
      expect(read(file)).not.toContain(PAT);
      expect(read(file)).toContain("vault://");
    }
  });

  test("no key: nothing on stdout, exit 0", async () => {
    expect(await hook("prompt-submit", s3Input(sb, "rename the function"))).toMatchObject({
      code: 0,
      stdout: "",
    });
  });

  test("stdin that is not JSON, or empty, and an unknown event: exit 0, nothing on stdout", async () => {
    for (const stdin of ["this is not json", "", "{"]) {
      expect(await hook("prompt-submit", stdin), stdin.slice(0, 12)).toMatchObject({
        code: 0,
        stdout: "",
      });
    }
    expect(await hook("nonsense", s3Input(sb, PAT))).toMatchObject({ code: 0, stdout: "" });
  });

  test("a prompt over 8 MiB is blocked in Codex's shape, key or not, because it cannot be checked", async () => {
    const before = (await secretsOf(sb)).length;
    for (const filler of [`${PAT} ${"a".repeat(9 * 1024 * 1024)}`, "a".repeat(9 * 1024 * 1024)]) {
      const res = await hook("prompt-submit", s3Input(sb, filler));
      expect(res.code, res.stderr).toBe(0);
      expect(JSON.parse(res.stdout)).toEqual({
        decision: "block",
        reason:
          "Prompt over 8 MiB; agent-vault cannot check it. Paste keys separately with agent-vault grab.",
      });
      expect(res.stdout + res.stderr).not.toContain(PAT);
    }
    expect((await secretsOf(sb)).length).toBe(before);
  });

  test("--probe blocks a key without storing it", async () => {
    const before = (await secretsOf(sb)).length;
    const res = await hook("prompt-submit", s3Input(sb, `k ${fakes.slack()}`), ["--probe"]);
    expect(res.code, res.stderr).toBe(0);
    expect(JSON.parse(res.stdout)).toEqual({ decision: "block", reason: expect.any(String) });
    expect((await secretsOf(sb)).length).toBe(before);
  });
});

describe("codex hook, vault unavailable", { timeout: TIMEOUT_MS }, () => {
  test("a key still blocks, with the init hint, and nothing leaks", async () => {
    const sb = sandbox(); // never initialised; no passphrase, so the keyfile daemon cannot start
    const PAT = fakes.githubPat();
    const res = await sb.cli(["hook", "codex", "prompt-submit"], {
      stdin: s3Input(sb, `k ${PAT}`),
      env: sandboxEnv(sb, { AGENT_VAULT_KEYFILE_PASSPHRASE: "" }),
    });
    expect(res.code, res.stderr).toBe(0);
    expect(JSON.parse(res.stdout)).toEqual({
      decision: "block",
      reason: "Key held back from the model. Run: agent-vault doctor codex",
    });
    expect(res.stdout + res.stderr).not.toContain(PAT);
    expect(await sb.daemonPid()).toBeNull();
  });
});

describe("install, doctor, uninstall", { timeout: TIMEOUT_MS }, () => {
  const sb = sandbox();
  const hooksFile = path.join(codexHome(sb), "hooks.json");
  const configFile = path.join(codexHome(sb), "config.toml");
  const run = (args: string[]) => sb.cli(args, { env: sandboxEnv(sb) });
  const originalConfig = [
    "# my codex setup",
    'model = "gpt-x"  # keep this',
    "",
    "[history]",
    "max_bytes = 4096",
    "",
  ].join("\n");
  const originalHooks = `${JSON.stringify(
    { hooks: { Stop: [{ hooks: [{ type: "command", command: "echo done" }] }] } },
    null,
    2,
  )}\n`;
  /** What pressing `t` in /hooks writes (S3: codex-trust-state.toml). */
  const trustText = (): string =>
    ["user_prompt_submit", "session_start"]
      .map(
        (e) =>
          `\n[hooks.state.${JSON.stringify(`${hooksFile}:${e}:0:0`)}]\ntrusted_hash = "sha256:${"ab".repeat(32)}"\n`,
      )
      .join("");

  test("install ends with the trust box; doctor is red until the hook is trusted, then passes; uninstall gives the files back", async () => {
    const init = await sb.cli(["init", "--keystore", "keyfile"]);
    expect(init.code, init.stderr).toBe(0);
    const pid = await sb.daemonPid();
    if (pid !== null) pidsSeen.add(pid);
    put(configFile, originalConfig);
    put(hooksFile, originalHooks);

    const installed = await run(["install", "codex"]);
    expect(installed.code, installed.stderr).toBe(0);
    // The box is the last output, and it holds the sentence whole.
    const tail = installed.stdout.trimEnd().split("\n");
    expect(tail.at(-1)).toMatch(/^\+-+\+$/);
    const boxText = tail
      .slice(tail.findIndex((l) => /^\+-+\+$/.test(l)))
      .filter((l) => l.startsWith("|"))
      .map((l) => l.slice(2, -2).trim())
      .join(" ");
    expect(boxText).toBe(TRUST_ACTION);

    expect(read(hooksFile).match(/ hook codex /g)).toHaveLength(2);
    expect(JSON.parse(read(hooksFile)).hooks.Stop).toHaveLength(1);
    expect(read(configFile)).toContain("[mcp_servers.agent-vault]");
    expect(read(configFile)).not.toContain("trusted_hash");

    const red = await run(["doctor", "codex"]);
    expect(red.code).toBe(1);
    expect(red.stdout).toMatch(
      /FAIL\s+trust\s+hook not trusted: Codex will skip it and send pasted keys to the model/,
    );
    expect(red.stdout).toContain("fix: run /hooks in Codex and press t");
    expect(red.stdout).toMatch(/ok\s+probe/);
    expect(red.stdout).toContain("1 of 9 checks failed");

    // Pressing `t` in Codex writes the trust tables (our hooks are group 0 of their events).
    fs.appendFileSync(configFile, trustText());
    const green = await run(["doctor", "codex"]);
    expect(green.code, green.stdout + green.stderr).toBe(0);
    expect(green.stdout).not.toContain("FAIL");
    expect(green.stdout).toMatch(
      /warn\s+history\s+blocked prompts typed in the TUI land in history\.jsonl until the next scrub/,
    );
    expect(green.stdout).toMatch(/info\s+sqlite\s+state_5\.sqlite/);
    expect(green.stdout).toContain("all 9 checks passed");

    // A second install keeps hooks.json byte for byte, so the trust holds, and asks for nothing.
    const hooksBefore = read(hooksFile);
    const configBefore = read(configFile);
    const again = await run(["install", "codex"]);
    expect(again.code, again.stderr).toBe(0);
    expect(read(hooksFile)).toBe(hooksBefore);
    expect(read(configFile)).toBe(configBefore);
    expect(again.stdout).not.toContain("ACTION NEEDED");

    const removed = await run(["uninstall", "codex"]);
    expect(removed.code, removed.stderr).toBe(0);
    expect(read(hooksFile)).toBe(originalHooks);
    // Only what Codex itself wrote (the trust tables) is left.
    expect(read(configFile)).toBe(originalConfig + trustText());

    const after = await run(["doctor", "codex"]);
    expect(after.code).toBe(1);
    expect(after.stdout).toMatch(/FAIL\s+hooks/);
    expect(after.stdout).toContain("fix: agent-vault install codex");
  });

  test("--no-history and --model-key (with --provider) are applied, and uninstall undoes them byte for byte", async () => {
    fs.rmSync(codexHome(sb), { recursive: true, force: true });
    put(configFile, originalConfig);
    put(hooksFile, originalHooks);
    await secretWith(sb, "openai/untagged", ["work"]);
    await secretWith(sb, "openai/helper", ["helper"]);

    const refused = await run(["install", "codex", "--model-key", "openai/untagged"]);
    expect(refused.code).toBe(1);
    expect(refused.stderr).toContain("tag it first: agent-vault set openai/untagged --tag helper");
    expect(read(configFile)).toBe(originalConfig);

    const ok = await run([
      "install",
      "codex",
      "--no-history",
      "--model-key",
      "openai/helper",
      "--provider",
      "mine",
    ]);
    expect(ok.code, ok.stderr).toBe(0);
    expect(ok.stdout).toMatch(/disables ALL Codex history/);
    const text = read(configFile);
    expect(text).toContain('[history]\npersistence = "none"\nmax_bytes = 4096');
    expect(text).toContain("[model_providers.mine.auth]");
    expect(text).toMatch(/args = \[.*"helper", "openai\/helper"\]/);

    const doctor = await run(["doctor", "codex"]);
    expect(doctor.stdout).toMatch(/ok\s+history\s+history\.persistence = "none"/);

    await run(["uninstall", "codex"]);
    expect(read(configFile)).toBe(originalConfig);
    expect(read(hooksFile)).toBe(originalHooks);
  });

  test("codex-only flags on another harness, and --provider without --model-key, are errors", async () => {
    const claude = await run(["install", "claude-code", "--no-history"]);
    expect(claude.code).toBe(1);
    expect(claude.stderr).toContain("only apply to codex");
    const lone = await run(["install", "codex", "--provider", "mine"]);
    expect(lone.code).toBe(1);
    expect(lone.stderr).toContain("--provider");
  });
});
