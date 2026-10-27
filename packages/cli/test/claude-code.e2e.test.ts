import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import type { SecretMeta } from "@agent-vault/core";
import { connect } from "@agent-vault/daemon";
import { getPaths, ipcEndpoint } from "@agent-vault/platform";
import { afterAll, describe, expect, test } from "vitest";
import { fakes } from "../../detect/test/fixtures/fake-keys.js";
import { alive, makeSandbox, type Sandbox } from "./harness.js";

// Each call starts node, and the first one in a sandbox also starts the daemon.
const TIMEOUT_MS = 60_000;

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

/**
 * The environment for every CLI call: never the real `claude` (PATH holds nothing, so `claude mcp
 * add` is "not installed" and the JSON fallback runs), and never a real CLAUDE_CONFIG_DIR.
 */
function sandboxEnv(sb: Sandbox, extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const empty = path.join(sb.dir, "empty-path");
  fs.mkdirSync(empty, { recursive: true });
  return { PATH: empty, Path: empty, CLAUDE_CONFIG_DIR: "", ...extra };
}

const put = (file: string, text: string): string => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
};
const read = (file: string): string => fs.readFileSync(file, "utf8");

/** What Claude Code sends a UserPromptSubmit hook (spike S3, "Real stdin"). */
const s3Input = (sb: Sandbox, prompt: string): string =>
  JSON.stringify({
    session_id: "0b7c1d3e-1111-4222-8333-444455556666",
    transcript_path: path.join(sb.dir, ".claude", "projects", "-proj", "0b7c1d3e.jsonl"),
    cwd: path.join(sb.dir, "proj"),
    prompt_id: "p-1",
    permission_mode: "default",
    hook_event_name: "UserPromptSubmit",
    prompt,
  });

const secretsOf = async (sb: Sandbox): Promise<SecretMeta[]> => {
  const client = await connect(ipcEndpoint(getPaths({ AGENT_VAULT_HOME: sb.home })));
  try {
    return await client.call<SecretMeta[]>("secret.list");
  } finally {
    client.close();
  }
};

describe("claude-code hook", { timeout: TIMEOUT_MS }, () => {
  const sb = sandbox();
  const PAT = fakes.githubPat();
  const OPENAI = fakes.openai();
  const hook = (event: string, stdin: string, flags: string[] = []) =>
    sb.cli(["hook", "claude-code", event, ...flags], { stdin, env: sandboxEnv(sb) });

  test("a prompt with 2 keys prints one block JSON and nothing else, and stores both", async () => {
    const init = await sb.cli(["init", "--keystore", "keyfile"]);
    expect(init.code, init.stderr).toBe(0);
    const pid = await sb.daemonPid();
    if (pid !== null) pidsSeen.add(pid);

    const res = await hook("prompt-submit", s3Input(sb, `use ${PAT} then ${OPENAI}`));
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout.trim().split("\n")).toHaveLength(1);
    const out = JSON.parse(res.stdout);
    expect(out).toEqual({
      decision: "block",
      reason: expect.stringMatching(/^Stored as \S+, \S+\. Re-send using vault:\/\/\S+\.$/),
      hookSpecificOutput: { hookEventName: "UserPromptSubmit", suppressOriginalPrompt: true },
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

  test("the transcript Claude writes afterwards is scrubbed by the scrub hook", async () => {
    const [first] = await secretsOf(sb);
    const input = JSON.parse(s3Input(sb, "x")) as { transcript_path: string };
    const history = path.join(sb.dir, ".claude", "history.jsonl");
    put(input.transcript_path, `${JSON.stringify({ type: "queue-operation", content: PAT })}\n`);
    put(history, `${JSON.stringify({ display: PAT })}\n`);
    expect(first).toBeDefined();

    const res = await hook(
      "scrub",
      JSON.stringify({ hook_event_name: "SessionEnd", session_id: "s", reason: "other" }),
    );
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout).toBe("");
    for (const file of [input.transcript_path, history]) {
      expect(read(file)).not.toContain(PAT);
      expect(read(file)).toContain("vault://");
    }
  });

  test("no key: nothing on stdout, exit 0", async () => {
    const res = await hook("prompt-submit", s3Input(sb, "rename the function"));
    expect(res).toMatchObject({ code: 0, stdout: "" });
  });

  test("stdin that is not JSON, or empty: exit 0, nothing on stdout", async () => {
    for (const stdin of ["this is not json", "", "{"]) {
      const res = await hook("prompt-submit", stdin);
      expect(res, `stdin ${stdin.slice(0, 12)}`).toMatchObject({ code: 0, stdout: "" });
    }
    // An unknown harness or event never wedges the harness either.
    expect(await hook("nonsense", s3Input(sb, PAT))).toMatchObject({ code: 0, stdout: "" });
    const unknown = await sb.cli(["hook", "nope", "prompt-submit"], {
      stdin: s3Input(sb, PAT),
      env: sandboxEnv(sb),
    });
    expect(unknown).toMatchObject({ code: 0, stdout: "" });
  });

  test("a prompt over 8 MiB is blocked, key or not, because it cannot be checked", async () => {
    const reason =
      "Prompt over 8 MiB; agent-vault cannot check it. Paste keys separately with agent-vault grab.";
    const before = (await secretsOf(sb)).length;
    for (const filler of [`${PAT} ${"a".repeat(9 * 1024 * 1024)}`, "a".repeat(9 * 1024 * 1024)]) {
      const res = await hook("prompt-submit", s3Input(sb, filler));
      expect(res.code, res.stderr).toBe(0);
      expect(JSON.parse(res.stdout)).toEqual({
        decision: "block",
        reason,
        hookSpecificOutput: { hookEventName: "UserPromptSubmit", suppressOriginalPrompt: true },
      });
      expect(res.stdout + res.stderr).not.toContain(PAT);
    }
    // Garbage that is also over the cap is blocked on the same grounds.
    const raw = await hook("prompt-submit", "b".repeat(9 * 1024 * 1024));
    expect(JSON.parse(raw.stdout)).toMatchObject({ decision: "block", reason });
    // A scrub event with a huge stdin does nothing.
    const scrub = await hook("scrub", "c".repeat(9 * 1024 * 1024));
    expect(scrub).toMatchObject({ code: 0, stdout: "" });
    expect((await secretsOf(sb)).length).toBe(before);
  });

  test("a prompt without a key never loads the rest of the CLI", async () => {
    // Log every module the process resolves; the fast path may touch detect, nothing more.
    const log = path.join(sb.dir, "resolved.log");
    const preload = put(
      path.join(sb.dir, "trace.mjs"),
      `import { appendFileSync } from "node:fs";
import { registerHooks } from "node:module";
registerHooks({
  resolve(spec, ctx, next) {
    const r = next(spec, ctx);
    appendFileSync(process.env.AV_TRACE, r.url + "\\n");
    return r;
  },
});
`,
    );
    const env = sandboxEnv(sb, {
      AV_TRACE: log,
      NODE_OPTIONS: `--import ${pathToFileURL(preload).href}`,
    });
    const clean = await sb.cli(["hook", "claude-code", "prompt-submit"], {
      stdin: s3Input(sb, "rename the function"),
      env,
    });
    expect(clean).toMatchObject({ code: 0, stdout: "" });
    const loaded = read(log);
    expect(loaded).toContain("/detect/");
    expect(loaded).not.toMatch(/program\.js|commander|\/adapters\/|\/daemon\//);

    // With a key the rest is loaded.
    fs.rmSync(log);
    const keyed = await sb.cli(["hook", "claude-code", "prompt-submit"], {
      stdin: s3Input(sb, `k ${fakes.slack()}`),
      env,
    });
    expect(JSON.parse(keyed.stdout)).toMatchObject({ decision: "block" });
    expect(read(log)).toMatch(/program\.js/);
  });

  test("--probe blocks a key without storing it", async () => {
    const before = (await secretsOf(sb)).length;
    const res = await hook("prompt-submit", s3Input(sb, `k ${fakes.slack()}`), ["--probe"]);
    expect(res.code, res.stderr).toBe(0);
    expect(JSON.parse(res.stdout)).toMatchObject({ decision: "block" });
    expect((await secretsOf(sb)).length).toBe(before);
  });
});

describe("claude-code hook, vault unavailable", { timeout: TIMEOUT_MS }, () => {
  test("a key still blocks, with the init hint, and nothing leaks", async () => {
    const sb = sandbox(); // never initialised; no passphrase, so the keyfile daemon cannot start
    const PAT = fakes.githubPat();
    const res = await sb.cli(["hook", "claude-code", "prompt-submit"], {
      stdin: s3Input(sb, `k ${PAT}`),
      env: sandboxEnv(sb, { AGENT_VAULT_KEYFILE_PASSPHRASE: "" }),
    });
    expect(res.code, res.stderr).toBe(0);
    expect(JSON.parse(res.stdout)).toEqual({
      decision: "block",
      reason: "Key held back from the model. Run: agent-vault doctor claude-code",
      hookSpecificOutput: { hookEventName: "UserPromptSubmit", suppressOriginalPrompt: true },
    });
    expect(res.stdout + res.stderr).not.toContain(PAT);
    expect(await sb.daemonPid()).toBeNull();

    const clean = await sb.cli(["hook", "claude-code", "prompt-submit"], {
      stdin: s3Input(sb, "hello"),
      env: sandboxEnv(sb, { AGENT_VAULT_KEYFILE_PASSPHRASE: "" }),
    });
    expect(clean).toMatchObject({ code: 0, stdout: "" });
  });
});

describe("claude-code hook, a key next to a multi-MiB blob", { timeout: TIMEOUT_MS }, () => {
  test("an sk-ant key plus a 5.6 MB base64 run blocks (the detector used to throw and allow)", async () => {
    const sb = sandbox(); // never initialised: the decision comes from detection alone
    const KEY = fakes.anthropic();
    const blob = randomBytes(4_200_000).toString("base64"); // one 5.6 MB run, over 5.33 MiB
    expect(blob.length).toBeGreaterThan(5.34 * 1024 * 1024);
    for (const prompt of [`${KEY} ${blob}`, `${blob} ${KEY}`]) {
      const res = await sb.cli(["hook", "claude-code", "prompt-submit"], {
        stdin: s3Input(sb, prompt),
        env: sandboxEnv(sb, { AGENT_VAULT_KEYFILE_PASSPHRASE: "" }),
      });
      expect(res.code, res.stderr).toBe(0);
      expect(JSON.parse(res.stdout)).toMatchObject({
        decision: "block",
        hookSpecificOutput: { suppressOriginalPrompt: true },
      });
      expect(res.stdout + res.stderr).not.toContain(KEY);
    }
  });
});

describe("install, doctor, uninstall", { timeout: TIMEOUT_MS }, () => {
  const sb = sandbox();
  const settings = path.join(sb.dir, ".claude", "settings.json");
  const claudeJson = path.join(sb.dir, ".claude.json");
  const run = (args: string[]) => sb.cli(args, { env: sandboxEnv(sb) });

  test("install adds the hooks and MCP, doctor passes with a live probe, uninstall restores the files", async () => {
    const init = await sb.cli(["init", "--keystore", "keyfile"]);
    expect(init.code, init.stderr).toBe(0);
    const pid = await sb.daemonPid();
    if (pid !== null) pidsSeen.add(pid);

    const originalSettings = `${JSON.stringify(
      { model: "opus", hooks: { Stop: [{ hooks: [{ type: "command", command: "echo done" }] }] } },
      null,
      2,
    )}\n`;
    const originalGlobal = `${JSON.stringify({ numStartups: 7 }, null, 2)}\n`;
    put(settings, originalSettings);
    put(claudeJson, originalGlobal);

    const installed = await run(["install", "claude-code"]);
    expect(installed.code, installed.stderr).toBe(0);
    const text = read(settings);
    expect(text.match(/ hook claude-code /g)).toHaveLength(3);
    expect(JSON.parse(text).hooks.Stop).toHaveLength(1);
    expect(JSON.parse(read(claudeJson)).mcpServers["agent-vault"]).toMatchObject({
      type: "stdio",
      args: expect.arrayContaining(["mcp"]),
    });

    const doctor = await run(["doctor", "claude-code"]);
    expect(doctor.code, doctor.stdout + doctor.stderr).toBe(0);
    expect(doctor.stdout).not.toContain("FAIL");
    expect(doctor.stdout).toMatch(/ok\s+probe/);
    expect(doctor.stdout).toContain("all 8 checks passed");

    const command = (JSON.parse(text).hooks.UserPromptSubmit[0].hooks[0] as { command: string })
      .command;
    expect(command).toMatch(/ hook claude-code prompt-submit$/);

    const removed = await run(["uninstall", "claude-code"]);
    expect(removed.code, removed.stderr).toBe(0);
    expect(read(settings)).toBe(originalSettings);
    expect(read(claudeJson)).toBe(originalGlobal);

    const after = await run(["doctor", "claude-code"]);
    expect(after.code).toBe(1);
    expect(after.stdout).toMatch(/FAIL\s+hooks/);
    expect(after.stdout).toContain("fix: agent-vault install claude-code");
  });

  test("--model-key is refused without the helper tag, then sets apiKeyHelper with it", async () => {
    const tag = (name: string, tags: string[]) => secretWith(sb, name, tags);
    await tag("anthropic/main", ["work"]);

    const refused = await run(["install", "claude-code", "--model-key", "anthropic/main"]);
    expect(refused.code).toBe(1);
    expect(refused.stderr).toContain("tag it first: agent-vault set anthropic/main --tag helper");

    await tag("anthropic/helper", ["helper"]);
    const ok = await run(["install", "claude-code", "--model-key", "anthropic/helper"]);
    expect(ok.code, ok.stderr).toBe(0);
    expect(JSON.parse(read(settings)).apiKeyHelper).toMatch(/ helper anthropic\/helper$/);
    const doctor = await run(["doctor", "claude-code"]);
    expect(doctor.code, doctor.stdout).toBe(0);

    await run(["uninstall", "claude-code"]);
    expect(JSON.parse(read(settings)).apiKeyHelper).toBeUndefined();
  });

  test("an unknown harness is an error", async () => {
    for (const cmd of ["install", "uninstall", "doctor"]) {
      const res = await run([cmd, "nope"]);
      expect(res.code).toBe(1);
      expect(res.stderr).toContain('unknown harness "nope"');
    }
  });
});

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
