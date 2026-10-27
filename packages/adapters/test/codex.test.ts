import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { SecretMeta } from "@agent-vault/core";
import { connect } from "@agent-vault/daemon";
import { ipcEndpoint } from "@agent-vault/platform";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakes } from "../../detect/test/fixtures/fake-keys.js";
import {
  AdapterError,
  CODEX_HOOK_MARKER,
  type CodexRunner,
  createCodexAdapter,
  EXPOSED_TAG,
  findHooks,
  type HookClient,
  heldBackReason,
  type ProbeRunner,
  parseJson,
  TRUST_ACTION,
  tagFirst,
} from "../src/index.js";
import { parseToml, tomlString } from "../src/toml-edit.js";
import { useBox } from "./helpers.js";

const box = useBox();

const PAT = fakes.githubPat();
const OPENAI = fakes.openai();

beforeEach(() => {
  // The daemon scrubs only files under the home directory, so the sandbox CODEX_HOME sits in it.
  box.codexHome = path.join(box.home, ".codex");
  fs.mkdirSync(box.codexHome, { recursive: true });
  // The sandbox rule: nothing here may reach the real home or the real ~/.codex.
  vi.stubEnv("HOME", box.home);
  vi.stubEnv("USERPROFILE", box.home);
  vi.stubEnv("CODEX_HOME", box.codexHome);
});
afterEach(() => vi.unstubAllEnvs());

const read = (file: string): string => fs.readFileSync(file, "utf8");
const write = (file: string, text: string): string => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
};
const hooksFile = () => path.join(box.codexHome, "hooks.json");
const configFile = () => path.join(box.codexHome, "config.toml");
const historyFile = () => path.join(box.codexHome, "history.jsonl");
const rollout = () => path.join(box.codexHome, "sessions", "2026", "10", "26", "rollout-s1.jsonl");
const stateFile = () => path.join(box.paths.dataDir, "adapters", "codex-state.json");
const backups = (): string[] =>
  fs.existsSync(box.paths.backupsDir) ? fs.readdirSync(box.paths.backupsDir) : [];
const config = (): Record<string, unknown> => parseToml(read(configFile()));

const secrets = async (): Promise<SecretMeta[]> =>
  (await box.client.call<SecretMeta[]>("secret.list")).sort((a, b) => a.name.localeCompare(b.name));

async function putSecret(name: string, tags: string[]): Promise<void> {
  await box.client.call("secret.put", {
    name,
    valueB64: Buffer.from("stand-in value, not a key").toString("base64"),
    tags,
  });
}

type Made = {
  adapter: ReturnType<typeof createCodexAdapter>;
  runCodex: ReturnType<typeof vi.fn<CodexRunner>>;
  runProbe: ReturnType<typeof vi.fn<ProbeRunner>>;
  connects: () => number;
  logs: string[];
  command: string[];
};

/** An adapter over the box's daemon. `codex` is a stub (code null: not installed). */
function make(
  extra: {
    main?: string;
    env?: NodeJS.ProcessEnv;
    client?: () => Promise<HookClient>;
    codexCode?: number | null;
    onCodex?: CodexRunner;
    probeStdout?: string;
  } = {},
): Made {
  const main = write(
    path.join(box.dir, "bin", extra.main ?? "main.js"),
    "// stands in for the CLI\n",
  );
  const command = [process.execPath, main];
  let n = 0;
  const logs: string[] = [];
  const runCodex = vi.fn<CodexRunner>(
    extra.onCodex ?? (async () => ({ code: extra.codexCode ?? null })),
  );
  const runProbe = vi.fn<ProbeRunner>(async () => ({
    code: 0,
    stdout: extra.probeStdout ?? JSON.stringify({ decision: "block", reason: "probe" }),
  }));
  const adapter = createCodexAdapter({
    command,
    home: box.home,
    env: extra.env ?? { CODEX_HOME: box.codexHome },
    stateFile: stateFile(),
    backupsDir: box.paths.backupsDir,
    runCodex,
    runProbe,
    client:
      extra.client ??
      (async () => {
        n++;
        return connect(ipcEndpoint(box.paths));
      }),
    log: (m) => logs.push(m),
  });
  return { adapter, runCodex, runProbe, connects: () => n, logs, command };
}

/** What `/hooks` then `t` writes for one hook (S3: codex-trust-state.toml). */
function trust(event: string, group: number, index: number, hash = randomHash()): string {
  const key = `${hooksFile()}:${event}:${group}:${index}`;
  fs.appendFileSync(configFile(), `\n[hooks.state.${tomlString(key)}]\ntrusted_hash = "${hash}"\n`);
  return hash;
}
const randomHash = (): string => `sha256:${randomBytes(32).toString("hex")}`;
function trustAll(): void {
  trust("user_prompt_submit", 0, 0);
  trust("session_start", 0, 0);
}

/** A config with user comments, odd spacing and several tables. */
const USER_CONFIG = [
  "# my codex setup: do not lose this comment",
  'model = "gpt-x"   # trailing comment',
  "",
  "[history]",
  "max_bytes = 4096  # keep",
  "",
  "[model_providers.local]",
  'name = "local"',
  "",
  "# the end",
  "",
].join("\n");

const USER_HOOKS = `${JSON.stringify(
  { hooks: { Stop: [{ hooks: [{ type: "command", command: "echo done" }] }] } },
  null,
  2,
)}\n`;

const promptInput = (prompt: string, extra: Record<string, unknown> = {}) => ({
  session_id: "s1",
  turn_id: "t1",
  transcript_path: rollout(),
  cwd: box.cwd,
  hook_event_name: "UserPromptSubmit",
  model: "gpt-x",
  permission_mode: "default",
  prompt,
  ...extra,
});

describe("install", () => {
  test("into an empty CODEX_HOME: hooks.json has the two hooks, config.toml parses and has the MCP table", async () => {
    const m = make();
    const report = await m.adapter.install({ home: box.home });

    const hooks = parseJson(read(hooksFile())).hooks as Record<string, unknown>;
    expect(Object.keys(hooks).sort()).toEqual(["SessionStart", "UserPromptSubmit"]);
    const found = findHooks(read(hooksFile()), CODEX_HOOK_MARKER);
    expect(found.map((h) => [h.event, h.group, h.index])).toEqual([
      ["UserPromptSubmit", 0, 0],
      ["SessionStart", 0, 0],
    ]);
    const prompt = found.find((h) => h.event === "UserPromptSubmit");
    const scrub = found.find((h) => h.event === "SessionStart");
    expect(prompt?.command).toMatch(/ hook codex prompt-submit$/);
    expect(scrub?.command).toMatch(/ hook codex scrub$/);
    // the hook command line writes paths with forward slashes on Windows
    expect(prompt?.command).toContain((m.command[1] as string).replaceAll("\\", "/"));
    expect(read(hooksFile())).not.toContain("SessionEnd");

    // `features.hooks` is on by default in Codex 0.164 (S3): it is not written.
    const toml = config();
    expect(toml.features).toBeUndefined();
    expect(toml.mcp_servers).toEqual({
      "agent-vault": { command: m.command[0], args: [m.command[1], "mcp"] },
    });
    expect(m.runCodex).toHaveBeenCalledWith([
      "mcp",
      "add",
      "agent-vault",
      "--",
      ...m.command,
      "mcp",
    ]);

    expect(report.harness).toBe("codex");
    expect(report.files).toEqual([hooksFile(), configFile()]);
    expect(report.backups).toEqual([]);
    expect(report.action).toBe(TRUST_ACTION);
    expect(TRUST_ACTION).toBe(
      "ACTION NEEDED: open Codex, run /hooks, select agent-vault and press t. Until then Codex skips the hook and pasted keys reach the model.",
    );
    expect(m.connects()).toBe(0);
  });

  test("a hook command is never forged into a trust entry", async () => {
    await make().adapter.install({ home: box.home });
    expect(read(configFile())).not.toContain("trusted_hash");
    expect(read(configFile())).not.toContain("hooks.state");
  });

  test("user comments, spacing and tables in config.toml survive; hooks.json keeps foreign hooks", async () => {
    write(configFile(), USER_CONFIG);
    write(hooksFile(), USER_HOOKS);
    const m = make();
    const report = await m.adapter.install({ home: box.home, noHistory: true });

    const text = read(configFile());
    for (const line of USER_CONFIG.split("\n")) expect(text).toContain(line);
    expect(parseJson(read(hooksFile())).hooks).toMatchObject({
      Stop: [{ hooks: [{ command: "echo done" }] }],
    });
    expect(report.backups).toHaveLength(2);
    for (const b of report.backups) expect(fs.existsSync(b)).toBe(true);
    expect(backups()).toHaveLength(2);
  });

  test("a second install leaves hooks.json and config.toml byte-identical (trust is kept)", async () => {
    write(hooksFile(), USER_HOOKS);
    write(configFile(), USER_CONFIG);
    const m = make();
    await m.adapter.install({ home: box.home });
    trustAll();
    const hooks = read(hooksFile());
    const toml = read(configFile());

    const again = await m.adapter.install({ home: box.home });
    expect(read(hooksFile())).toBe(hooks);
    expect(read(configFile())).toBe(toml);
    expect(again.files).toEqual([]);
    expect(again.backups).toEqual([]);
    // Already trusted and unchanged: nothing to ask for.
    expect(again.action).toBeUndefined();
    expect(again.notes.join("\n")).toContain("already trusted");
  });

  test("an install whose hook is not trusted yet asks again", async () => {
    const m = make();
    await m.adapter.install({ home: box.home });
    const again = await m.adapter.install({ home: box.home });
    expect(again.action).toBe(TRUST_ACTION);
  });

  test("a second install keeps our hook where it is, even with foreign hooks after it", async () => {
    const m = make();
    await m.adapter.install({ home: box.home });
    const foreign = { hooks: [{ type: "command", command: "echo later" }] };
    const doc = parseJson(read(hooksFile())) as { hooks: Record<string, unknown[]> };
    doc.hooks.UserPromptSubmit?.push(foreign);
    write(hooksFile(), `${JSON.stringify(doc, null, 2)}\n`);

    await m.adapter.install({ home: box.home });
    const after = parseJson(read(hooksFile())) as { hooks: Record<string, { hooks: unknown[] }[]> };
    expect(after.hooks.UserPromptSubmit).toHaveLength(2);
    expect(findHooks(read(hooksFile()), CODEX_HOOK_MARKER).map((h) => h.group)).toEqual([0, 0]);
    expect(read(hooksFile())).toBe(`${JSON.stringify(doc, null, 2)}\n`);
  });

  test("a missing hook is added without moving the one that is there", async () => {
    const m = make();
    await m.adapter.install({ home: box.home });
    const scrub = findHooks(read(hooksFile()), CODEX_HOOK_MARKER).find(
      (h) => h.event === "SessionStart",
    );
    const doc = parseJson(read(hooksFile())) as { hooks: Record<string, unknown> };
    delete doc.hooks.SessionStart;
    write(hooksFile(), `${JSON.stringify(doc, null, 2)}\n`);
    const before = read(hooksFile());

    await m.adapter.install({ home: box.home });
    const after = read(hooksFile());
    expect(findHooks(after, CODEX_HOOK_MARKER)).toHaveLength(2);
    const prompt = findHooks(after, CODEX_HOOK_MARKER).find((h) => h.event === "UserPromptSubmit");
    expect(prompt).toMatchObject({ group: 0, index: 0 });
    expect(
      findHooks(after, CODEX_HOOK_MARKER).find((h) => h.event === "SessionStart")?.command,
    ).toBe(scrub?.command);
    expect(after.startsWith(before.slice(0, before.indexOf('"UserPromptSubmit"')))).toBe(true);
  });

  test("a hook that points at another binary is replaced, and the old trust no longer counts", async () => {
    const first = make();
    await first.adapter.install({ home: box.home });
    trustAll();
    expect((await first.adapter.doctor(box.home)).checks.find((c) => c.name === "trust")?.ok).toBe(
      true,
    );

    const second = make({ main: "moved.js" });
    const report = await second.adapter.install({ home: box.home });
    const found = findHooks(read(hooksFile()), CODEX_HOOK_MARKER);
    expect(found).toHaveLength(2);
    for (const h of found) expect(h.command).toContain("moved.js");
    expect(report.action).toBe(TRUST_ACTION);

    // The old trusted_hash is still in config.toml, for a command that is gone.
    const trustCheck = (await second.adapter.doctor(box.home)).checks.find(
      (c) => c.name === "trust",
    );
    expect(trustCheck?.ok).toBe(false);
    // Pressing t again writes a new hash.
    const toml = read(configFile()).replace(/\n\[hooks\.state[^\n]*\ntrusted_hash[^\n]*\n/g, "\n");
    write(configFile(), toml);
    trustAll();
    expect((await second.adapter.doctor(box.home)).checks.find((c) => c.name === "trust")?.ok).toBe(
      true,
    );
  });

  test("a command that is not absolute is refused before anything is written", async () => {
    const bare = createCodexAdapter({
      command: ["agent-vault"],
      home: box.home,
      env: { CODEX_HOME: box.codexHome },
      stateFile: stateFile(),
      client: () => Promise.reject(new Error("never connected")),
    });
    await expect(bare.install({ home: box.home })).rejects.toThrow(AdapterError);
    expect(fs.existsSync(hooksFile())).toBe(false);
    expect(fs.existsSync(configFile())).toBe(false);
  });

  test("a config.toml or hooks.json that does not parse is refused and left alone", async () => {
    write(configFile(), "model = = 1\n");
    await expect(make().adapter.install({ home: box.home })).rejects.toThrow(
      /config\.toml is not usable/,
    );
    expect(read(configFile())).toBe("model = = 1\n");
    expect(fs.existsSync(hooksFile())).toBe(false);

    write(configFile(), "");
    write(hooksFile(), "{ nope");
    await expect(make().adapter.install({ home: box.home })).rejects.toThrow(
      /hooks\.json is not usable/,
    );
    write(hooksFile(), '{"hooks": []}');
    await expect(make().adapter.install({ home: box.home })).rejects.toThrow(
      /"hooks" is not an object/,
    );
    expect(backups()).toEqual([]);
  });

  test("CODEX_HOME decides where everything goes; without it, ~/.codex", async () => {
    const elsewhere = path.join(box.dir, "elsewhere");
    const m = make({ env: { CODEX_HOME: elsewhere } });
    await m.adapter.install({ home: box.home });
    expect(fs.existsSync(path.join(elsewhere, "hooks.json"))).toBe(true);
    expect(fs.existsSync(hooksFile())).toBe(false);

    const dflt = make({ env: {} });
    await dflt.adapter.install({ home: box.home });
    expect(fs.existsSync(path.join(box.home, ".codex", "hooks.json"))).toBe(true);
    expect(await dflt.adapter.detect(box.home)).toBe(true);
    expect(
      await make({ env: { CODEX_HOME: path.join(box.dir, "nope") } }).adapter.detect(box.home),
    ).toBe(false);
  });
});

describe("MCP", () => {
  test("`codex mcp add` is tried first, with CODEX_HOME; when it works, nothing is appended by hand", async () => {
    write(configFile(), USER_CONFIG);
    const m = make({
      onCodex: async (args) => {
        fs.appendFileSync(
          configFile(),
          `\n[mcp_servers.agent-vault]\ncommand = ${tomlString(args[4] as string)}\n`,
        );
        return { code: 0 };
      },
    });
    const report = await m.adapter.install({ home: box.home });
    expect(m.runCodex).toHaveBeenCalledTimes(1);
    expect(report.notes.join("\n")).toContain("codex mcp add");
    expect(read(configFile()).match(/mcp_servers\.agent-vault/g)).toHaveLength(1);
  });

  test("with `codex` absent, or failing, or claiming success without writing, the table is appended", async () => {
    for (const code of [null, 1, 0]) {
      fs.rmSync(box.codexHome, { recursive: true, force: true });
      fs.rmSync(stateFile(), { force: true });
      write(configFile(), USER_CONFIG);
      const m = make({ codexCode: code });
      const report = await m.adapter.install({ home: box.home });
      expect(config().mcp_servers, `code ${code}`).toEqual({
        "agent-vault": { command: m.command[0], args: [m.command[1], "mcp"] },
      });
      expect(read(configFile()).startsWith(USER_CONFIG)).toBe(true);
      expect(report.notes.join("\n")).toContain("written to");
    }
  });

  test("a config.toml the table cannot be appended to is refused before hooks.json is touched", async () => {
    const inline = 'mcp_servers = { other = { command = "x" } }\n';
    write(configFile(), inline);
    await expect(make().adapter.install({ home: box.home })).rejects.toThrow(
      /cannot be edited safely/,
    );
    expect(read(configFile())).toBe(inline);
    expect(fs.existsSync(hooksFile())).toBe(false);
    expect(fs.existsSync(stateFile())).toBe(false);
  });

  test("uninstall removes exactly the appended table", async () => {
    write(configFile(), USER_CONFIG);
    const m = make();
    await m.adapter.install({ home: box.home });
    await m.adapter.uninstall(box.home);
    expect(read(configFile())).toBe(USER_CONFIG);
    expect(m.runCodex).toHaveBeenCalledTimes(1); // only the `add`; the table was ours, so no `remove`
  });

  test("uninstall after a `codex mcp add` runs `codex mcp remove agent-vault`", async () => {
    write(configFile(), USER_CONFIG);
    const m = make({
      onCodex: async (args) => {
        if (args[1] === "add") {
          fs.appendFileSync(configFile(), '\n[mcp_servers.agent-vault]\ncommand = "x"\n');
        } else {
          write(configFile(), USER_CONFIG); // what `codex mcp remove` does
        }
        return { code: 0 };
      },
    });
    await m.adapter.install({ home: box.home });
    await m.adapter.uninstall(box.home);
    expect(m.runCodex).toHaveBeenLastCalledWith(["mcp", "remove", "agent-vault"]);
    expect(read(configFile())).toBe(USER_CONFIG);
  });

  test("an entry that is already ours is left alone; a different one is reported, not overwritten", async () => {
    const m = make();
    const mine = `[mcp_servers.agent-vault]\ncommand = ${tomlString(m.command[0] as string)}\nargs = [${tomlString(m.command[1] as string)}, "mcp"]\n`;
    write(configFile(), `${USER_CONFIG}\n${mine}`);
    const same = await m.adapter.install({ home: box.home });
    expect(read(configFile())).toBe(`${USER_CONFIG}\n${mine}`);
    expect(same.notes.join("\n")).toContain("already registered");
    expect(m.runCodex).not.toHaveBeenCalled();

    const stale = `[mcp_servers.agent-vault]\ncommand = "/old/place/agent-vault"\nargs = ["mcp"]\n`;
    write(configFile(), `${USER_CONFIG}\n${stale}`);
    const other = await m.adapter.install({ home: box.home });
    expect(read(configFile())).toBe(`${USER_CONFIG}\n${stale}`);
    expect(other.notes.join("\n")).toMatch(/different command/);
    // and uninstall does not touch an entry it did not add
    await m.adapter.uninstall(box.home);
    expect(read(configFile())).toBe(`${USER_CONFIG}\n${stale}`);
  });
});

describe("--no-history", () => {
  test("appends [history] persistence = none when there is no history table, and undoes to the same bytes", async () => {
    const original = 'model = "x"\n';
    write(configFile(), original);
    const m = make();
    const report = await m.adapter.install({ home: box.home, noHistory: true });
    expect((config().history as Record<string, unknown>).persistence).toBe("none");
    expect(report.notes.join("\n")).toMatch(/disables ALL Codex history/);
    await m.adapter.uninstall(box.home);
    expect(read(configFile())).toBe(original);
  });

  test("inserts one line under an existing [history] header, and undoes to the same bytes", async () => {
    write(configFile(), USER_CONFIG);
    const m = make();
    await m.adapter.install({ home: box.home, noHistory: true });
    expect(read(configFile())).toContain(
      '[history]\npersistence = "none"\nmax_bytes = 4096  # keep',
    );
    expect(config().history).toEqual({ persistence: "none", max_bytes: 4096 });
    await m.adapter.uninstall(box.home);
    expect(read(configFile())).toBe(USER_CONFIG);
  });

  test("it is opt-in: without the flag, history is not touched", async () => {
    write(configFile(), USER_CONFIG);
    await make().adapter.install({ home: box.home });
    expect(config().history).toEqual({ max_bytes: 4096 });
  });

  test("already none is left alone and not removed by uninstall; any other value is refused", async () => {
    const none = '[history]\npersistence = "none"\n';
    write(configFile(), none);
    const m = make();
    await m.adapter.install({ home: box.home, noHistory: true });
    await m.adapter.uninstall(box.home);
    expect(read(configFile())).toBe(none);

    const saved = '[history]\npersistence = "save-all"\n';
    write(configFile(), saved);
    await expect(m.adapter.install({ home: box.home, noHistory: true })).rejects.toThrow(
      /already sets history\.persistence/,
    );
    expect(read(configFile())).toBe(saved);
  });
});

describe("--model-key", () => {
  test("is refused without the helper tag, and nothing is written", async () => {
    await putSecret("openai/main", ["work"]);
    const m = make();
    await expect(m.adapter.install({ home: box.home, modelKey: "openai/main" })).rejects.toThrow(
      tagFirst("openai/main"),
    );
    await expect(m.adapter.install({ home: box.home, modelKey: "nope" })).rejects.toThrow(
      AdapterError,
    );
    expect(fs.existsSync(hooksFile())).toBe(false);
    expect(fs.existsSync(configFile())).toBe(false);
  });

  test("inserts the auth table for the openai provider by default, and undoes to the same bytes", async () => {
    await putSecret("openai/helper", ["helper"]);
    write(configFile(), USER_CONFIG);
    const m = make();
    const report = await m.adapter.install({ home: box.home, modelKey: "openai/helper" });
    // Codex's ModelProviderAuthInfo is `command` (a program) plus `args`, not one array.
    expect((config().model_providers as Record<string, unknown>).openai).toEqual({
      auth: { command: m.command[0], args: [m.command[1], "helper", "openai/helper"] },
    });
    expect(report.notes.join("\n")).toContain("openai/helper");
    await m.adapter.uninstall(box.home);
    expect(read(configFile())).toBe(USER_CONFIG);
  });

  test("installing again with the same key and provider is idempotent, not a refusal", async () => {
    await putSecret("local/helper", ["helper"]);
    write(configFile(), USER_CONFIG);
    const m = make();
    const opts = { home: box.home, modelKey: "local/helper", provider: "custom" };
    await m.adapter.install(opts);
    const once = read(configFile());
    const again = await m.adapter.install(opts);
    expect(read(configFile())).toBe(once);
    expect(again.notes.join("\n")).toContain("already gets its key from local/helper");
    await m.adapter.uninstall(box.home);
    expect(read(configFile())).toBe(USER_CONFIG);

    // A different auth for that provider is still a conflict.
    await m.adapter.install(opts);
    await putSecret("local/other", ["helper"]);
    await expect(
      m.adapter.install({ home: box.home, modelKey: "local/other", provider: "custom" }),
    ).rejects.toThrow(/already sets auth/);
  });

  test("--provider picks another provider, existing or new", async () => {
    await putSecret("local/helper", ["helper"]);
    write(configFile(), USER_CONFIG);
    const m = make();
    await m.adapter.install({ home: box.home, modelKey: "local/helper", provider: "local" });
    expect((config().model_providers as Record<string, unknown>).local).toMatchObject({
      name: "local",
      auth: { args: [m.command[1], "helper", "local/helper"] },
    });
    await m.adapter.uninstall(box.home);
    expect(read(configFile())).toBe(USER_CONFIG);
  });

  test("is refused when that provider already has an auth, and for a provider id that is not a bare key", async () => {
    await putSecret("openai/helper", ["helper"]);
    const taken = '[model_providers.openai.auth]\ncommand = "/bin/other"\n';
    write(configFile(), taken);
    const m = make();
    await expect(m.adapter.install({ home: box.home, modelKey: "openai/helper" })).rejects.toThrow(
      /already sets auth for model provider "openai"/,
    );
    expect(read(configFile())).toBe(taken);
    expect(fs.existsSync(hooksFile())).toBe(false);

    await expect(
      m.adapter.install({ home: box.home, modelKey: "openai/helper", provider: 'a"b' }),
    ).rejects.toThrow(AdapterError);
    await expect(m.adapter.install({ home: box.home, provider: "local" })).rejects.toThrow(
      /--provider/,
    );
  });
});

describe("uninstall", () => {
  test("gives config.toml and hooks.json back byte for byte, with every option on", async () => {
    await putSecret("openai/helper", ["helper"]);
    write(configFile(), USER_CONFIG);
    write(hooksFile(), USER_HOOKS);
    const m = make();
    await m.adapter.install({
      home: box.home,
      noHistory: true,
      modelKey: "openai/helper",
    });
    expect(read(configFile())).not.toBe(USER_CONFIG);
    await m.adapter.uninstall(box.home);
    expect(read(configFile())).toBe(USER_CONFIG);
    expect(read(hooksFile())).toBe(USER_HOOKS);
  });

  test("with CRLF line endings and no final newline", async () => {
    const crlf = '# c\r\nmodel = "x"\r\n[history]\r\nmax_bytes = 1';
    write(configFile(), crlf);
    const m = make();
    await m.adapter.install({ home: box.home, noHistory: true });
    expect(read(configFile())).toContain('[history]\r\npersistence = "none"\r\nmax_bytes = 1');
    expect(config().mcp_servers).toBeDefined();
    await m.adapter.uninstall(box.home);
    expect(read(configFile())).toBe(crlf);
  });

  test("files that install created are deleted again", async () => {
    const m = make();
    await m.adapter.install({ home: box.home, noHistory: true });
    expect(fs.existsSync(hooksFile())).toBe(true);
    await m.adapter.uninstall(box.home);
    expect(fs.existsSync(hooksFile())).toBe(false);
    expect(fs.existsSync(configFile())).toBe(false);
    expect(fs.existsSync(stateFile())).toBe(false);
  });

  test("the trust entries Codex wrote are left alone, and everything else goes", async () => {
    write(configFile(), USER_CONFIG);
    const m = make();
    await m.adapter.install({ home: box.home });
    trustAll();
    await m.adapter.uninstall(box.home);
    const left = read(configFile());
    expect(left.startsWith(USER_CONFIG)).toBe(true);
    expect(left).not.toContain("mcp_servers");
    expect(left).toContain("trusted_hash");
  });

  test("a hook added by hand after ours stays, and a second uninstall is a no-op", async () => {
    write(hooksFile(), USER_HOOKS);
    const m = make();
    await m.adapter.install({ home: box.home });
    await m.adapter.uninstall(box.home);
    await m.adapter.uninstall(box.home);
    expect(read(hooksFile())).toBe(USER_HOOKS);
  });

  test("only entries that start with our command words are ours", async () => {
    const m = make();
    const lookalike = `echo run ${m.command[1]} hook codex prompt-submit please`;
    const foreign = `/opt/other/tool hook codex scrub`;
    write(
      hooksFile(),
      `${JSON.stringify(
        {
          hooks: {
            UserPromptSubmit: [{ hooks: [{ type: "command", command: lookalike }] }],
            SessionStart: [{ hooks: [{ type: "command", command: foreign }] }],
          },
        },
        null,
        2,
      )}\n`,
    );
    const before = read(hooksFile());
    await m.adapter.install({ home: box.home });
    const commands = parseJson(read(hooksFile())).hooks as Record<
      string,
      { hooks: { command: string }[] }[]
    >;
    expect(commands.UserPromptSubmit?.map((g) => g.hooks[0]?.command)).toContain(lookalike);
    expect(commands.SessionStart?.map((g) => g.hooks[0]?.command)).toContain(foreign);
    expect(commands.UserPromptSubmit).toHaveLength(2);
    await m.adapter.uninstall(box.home);
    expect(read(hooksFile())).toBe(before);
  });

  test("a hooks object the user already had stays, an empty one we made goes", async () => {
    const m = make();
    write(hooksFile(), '{ "hooks": {} }\n');
    await m.adapter.install({ home: box.home });
    await m.adapter.uninstall(box.home);
    expect(read(hooksFile())).toBe('{ "hooks": {} }\n');

    fs.rmSync(hooksFile());
    await m.adapter.install({ home: box.home });
    await m.adapter.uninstall(box.home);
    expect(fs.existsSync(hooksFile())).toBe(false);
  });

  test("blockOutput is exactly {decision, reason}", () => {
    const out = make().adapter.blockOutput("because");
    expect(JSON.stringify(out)).toBe('{"decision":"block","reason":"because"}');
  });

  test("undo never reaches a line in another table: a profile's persistence stays", async () => {
    const original = '[profiles.x.history]\npersistence = "none"\n\n[history]\nmax_bytes = 5\n';
    write(configFile(), original);
    const m = make();
    await m.adapter.install({ home: box.home, noHistory: true });
    write(configFile(), read(configFile()).replace("[history]\n", "[history]\n# mine\n"));
    await m.adapter.uninstall(box.home);
    expect(read(configFile())).toBe(
      '[profiles.x.history]\npersistence = "none"\n\n[history]\n# mine\nmax_bytes = 5\n',
    );
    expect(m.logs).toEqual([]);
  });

  test("an edit that cannot be undone is left and reported, by its first line", async () => {
    write(configFile(), USER_CONFIG);
    const m = make();
    await m.adapter.install({ home: box.home, noHistory: true });
    const edited = read(configFile())
      .replace('persistence = "none"\n', "")
      .replace(
        /\n\[mcp_servers\.agent-vault\][^[]*/,
        '\n[mcp_servers.agent-vault]\ncommand = "x"\nextra = 1\n',
      );
    write(configFile(), edited);
    await m.adapter.uninstall(box.home);
    const said = m.logs.join("\n");
    expect(said).toContain(
      `left persistence = "none" in ${configFile()} (it moved or was changed); remove it by hand`,
    );
    expect(said).toContain(
      `left [mcp_servers.agent-vault] in ${configFile()} (it moved or was changed); remove it by hand`,
    );
    expect(read(configFile())).toContain("extra = 1");
  });

  test("removing our group says when it moved the user's hooks after it", async () => {
    const m = make();
    await m.adapter.install({ home: box.home });
    const doc = parseJson(read(hooksFile())) as { hooks: Record<string, unknown[]> };
    doc.hooks.UserPromptSubmit?.push({ hooks: [{ type: "command", command: "echo later" }] });
    write(hooksFile(), `${JSON.stringify(doc, null, 2)}\n`);
    await m.adapter.uninstall(box.home);
    expect(m.logs.join("\n")).toContain(
      "your hooks after agent-vault's moved position; Codex may now treat them as untrusted; re-run /hooks",
    );

    // A user hook that sat before ours does not move.
    const quiet = make();
    write(hooksFile(), USER_HOOKS);
    await quiet.adapter.install({ home: box.home });
    await quiet.adapter.uninstall(box.home);
    expect(quiet.logs).toEqual([]);
  });

  test("with nothing installed, nothing is created", async () => {
    await make().adapter.uninstall(box.home);
    expect(fs.existsSync(hooksFile())).toBe(false);
    expect(fs.existsSync(configFile())).toBe(false);
  });
});

describe("doctor", () => {
  test("a wrapped MCP server (TOML command/args) whose node or main.js is gone is red", async () => {
    const m = make();
    const gone = path.join(box.dir, "old", "packages", "cli", "dist", "main.js");
    write(
      configFile(),
      `[mcp_servers.search]\ncommand = ${JSON.stringify(process.execPath)}\nargs = [${JSON.stringify(gone)}, "run", "--bundle", "mcp-search", "--", "npx", "search"]\n`,
    );
    const check = (await m.adapter.doctor(box.home)).checks.find(
      (c) => c.name === "wrapped MCP servers",
    );
    expect(check).toMatchObject({
      ok: false,
      detail: `search in ${configFile()} runs ${gone}, which does not exist`,
    });

    write(
      configFile(),
      `[mcp_servers.search]\ncommand = ${JSON.stringify(m.command[0])}\nargs = [${JSON.stringify(m.command[1])}, "run", "--bundle", "mcp-search", "--", "npx"]\n`,
    );
    const fine = (await m.adapter.doctor(box.home)).checks.find(
      (c) => c.name === "wrapped MCP servers",
    );
    expect(fine).toMatchObject({
      ok: true,
      detail: "1 run through agent-vault, and each command exists",
    });
  });

  async function installed(extra: Parameters<typeof make>[0] = {}) {
    const m = make(extra);
    await m.adapter.install({ home: box.home });
    return m;
  }
  const check = async (m: Made, name: string) =>
    (await m.adapter.doctor(box.home)).checks.find((c) => c.name === name);

  test("an untrusted hook is red, with the fix; trusted is green with the re-check note", async () => {
    const m = await installed();
    const red = await check(m, "trust");
    expect(red).toMatchObject({
      ok: false,
      detail: expect.stringContaining(
        "hook not trusted: Codex will skip it and send pasted keys to the model",
      ),
      fix: "run /hooks in Codex and press t",
    });
    expect((await m.adapter.doctor(box.home)).ok).toBe(false);

    trustAll();
    const green = await check(m, "trust");
    expect(green?.ok).toBe(true);
    expect(green?.detail).toMatch(/editing the hook command un-trusts it/);
  });

  test("trust is looked up by OUR hook's group and index, not by position 0:0", async () => {
    write(
      hooksFile(),
      `${JSON.stringify({ hooks: { UserPromptSubmit: [{ hooks: [{ type: "command", command: "echo first" }] }] } }, null, 2)}\n`,
    );
    const m = await installed();
    expect(
      findHooks(read(hooksFile()), CODEX_HOOK_MARKER).find((h) => h.event === "UserPromptSubmit"),
    ).toMatchObject({
      group: 1,
      index: 0,
    });
    trust("user_prompt_submit", 0, 0); // someone else's hook
    expect((await check(m, "trust"))?.ok).toBe(false);
    trust("user_prompt_submit", 1, 0);
    expect((await check(m, "trust"))?.ok).toBe(true);
  });

  test("a trust table without a trusted_hash does not count", async () => {
    const m = await installed();
    fs.appendFileSync(
      configFile(),
      `\n[hooks.state.${tomlString(`${hooksFile()}:user_prompt_submit:0:0`)}]\nnote = "x"\n`,
    );
    expect((await check(m, "trust"))?.ok).toBe(false);
  });

  test("a scrub hook that is not trusted is a warning, not red", async () => {
    const m = await installed();
    trust("user_prompt_submit", 0, 0);
    const c = await check(m, "trust");
    expect(c).toMatchObject({ ok: true, severity: "warn" });
    expect(c?.detail).toMatch(/SessionStart/);
  });

  test("everything installed and trusted passes, with the probe run through the installed command", async () => {
    await putSecret("x/y", ["helper"]);
    const m = await installed();
    trustAll();
    const report = await m.adapter.doctor(box.home);
    expect(report.checks.map((c) => c.name)).toEqual([
      "hooks",
      "trust",
      "features",
      "daemon",
      "vault",
      "mcp",
      "probe",
      "wrapped MCP servers",
      "history",
      "sqlite",
    ]);
    expect(report.checks.filter((c) => !c.ok)).toEqual([]);
    expect(report.ok).toBe(true);
    const [command, stdin] = m.runProbe.mock.calls[0] as [string, string];
    expect(command).toMatch(/ hook codex prompt-submit --probe$/);
    const sent = JSON.parse(stdin) as Record<string, unknown>;
    expect(sent).toMatchObject({ hook_event_name: "UserPromptSubmit" });
    expect(typeof sent.prompt).toBe("string");
    expect(typeof sent.turn_id).toBe("string");
    // The probe key is made at run time and never stored.
    expect(await secrets()).toHaveLength(1);
  });

  test("a probe that does not block is red", async () => {
    const m = await installed({ probeStdout: "" });
    expect(await check(m, "probe")).toMatchObject({ ok: false, fix: "agent-vault install codex" });
  });

  test("features.hooks = false (or the old codex_hooks = false) is red", async () => {
    const m = await installed();
    for (const line of ["hooks = false", "codex_hooks = false"]) {
      write(configFile(), `${read(configFile())}\n[features]\n${line}\n`);
      expect(await check(m, "features"), line).toMatchObject({ ok: false });
      write(configFile(), read(configFile()).replace(`\n[features]\n${line}\n`, ""));
    }
    expect((await check(m, "features"))?.ok).toBe(true);
  });

  test("history: none is ok; anything else is a warning that names history.jsonl", async () => {
    const m = await installed();
    const warn = await check(m, "history");
    expect(warn).toMatchObject({ ok: true, severity: "warn" });
    expect(warn?.detail).toContain(
      "blocked prompts typed in the TUI land in history.jsonl until the next scrub",
    );
    await m.adapter.install({ home: box.home, noHistory: true });
    const fine = await check(m, "history");
    expect(fine?.ok).toBe(true);
    expect(fine?.severity).toBeUndefined();
  });

  test("the SQLite stores are an info line, never red", async () => {
    const m = await installed();
    const c = await check(m, "sqlite");
    expect(c).toMatchObject({ ok: true, severity: "info" });
    expect(c?.detail).toContain("state_5.sqlite");
    expect(c?.detail).toContain("thread_history_1.sqlite");
  });

  test("trust says it checks presence only, in both outcomes", async () => {
    const m = await installed();
    const proof = "presence only; run a real Codex prompt with a fake key to prove it fires";
    expect((await check(m, "trust"))?.detail).toContain(proof);
    trustAll();
    expect((await check(m, "trust"))?.detail).toContain(proof);
  });

  test("a CODEX_HOME outside the home directory, and an auth table for openai, each get an info line", async () => {
    const m = await installed();
    expect(await check(m, "scope")).toBeUndefined();
    expect(await check(m, "provider")).toBeUndefined();

    await putSecret("openai/helper", ["helper"]);
    await m.adapter.install({ home: box.home, modelKey: "openai/helper" });
    expect(await check(m, "provider")).toMatchObject({ ok: true, severity: "info" });

    const elsewhere = path.join(box.dir, "elsewhere");
    const out = make({ env: { CODEX_HOME: elsewhere } });
    await out.adapter.install({ home: box.home });
    const scope = (await out.adapter.doctor(box.home)).checks.find((c) => c.name === "scope");
    expect(scope).toMatchObject({ ok: true, severity: "info" });
    expect(scope?.detail).toContain("scrubs only files under it");
  });

  test("a hook that moved is red, even when the trust entry at its new place is someone else's", async () => {
    const m = await installed();
    trustAll();
    expect((await check(m, "trust"))?.ok).toBe(true);

    // A hook is added before ours: ours is now group 1, and group 1 has a trust entry already.
    const doc = parseJson(read(hooksFile())) as { hooks: Record<string, unknown[]> };
    doc.hooks.UserPromptSubmit?.unshift({ hooks: [{ type: "command", command: "echo first" }] });
    write(hooksFile(), `${JSON.stringify(doc, null, 2)}\n`);
    const theirs = trust("user_prompt_submit", 1, 0);
    const red = await check(m, "trust");
    expect(red).toMatchObject({
      ok: false,
      detail: expect.stringContaining(
        "our hook moved from 0:0 to 1:0; Codex keys trust by position; re-run /hooks and trust it",
      ),
    });

    // After a re-install, the hash at the new place is still not ours, until Codex writes a new one.
    await m.adapter.install({ home: box.home });
    expect((await check(m, "trust"))?.ok).toBe(false);
    write(configFile(), read(configFile()).replace(theirs, randomHash()));
    expect((await check(m, "trust"))?.ok).toBe(true);
  });

  test("a [mcp_servers.agent-vault] that is not ours is red with 'different command'", async () => {
    const m = await installed();
    write(
      configFile(),
      '[mcp_servers.agent-vault]\ncommand = "/old/place/agent-vault"\nargs = ["mcp"]\n',
    );
    expect(await check(m, "mcp")).toMatchObject({
      ok: false,
      detail: expect.stringContaining("different command"),
    });
  });

  test("hooks missing, or pointing at a binary that is gone, are red with the fix", async () => {
    const m = make();
    let report = await m.adapter.doctor(box.home);
    expect(report.checks.find((c) => c.name === "hooks")).toMatchObject({
      ok: false,
      fix: "agent-vault install codex",
    });
    expect(report.checks.find((c) => c.name === "mcp")?.ok).toBe(false);

    await m.adapter.install({ home: box.home });
    fs.rmSync(m.command[1] as string);
    report = await m.adapter.doctor(box.home);
    expect(report.checks.find((c) => c.name === "hooks")?.detail).toContain("does not exist");
  });

  test("a daemon that cannot be reached is red; the other checks still run", async () => {
    const m = await installed({ client: () => Promise.reject(new Error("connect ECONNREFUSED")) });
    const report = await m.adapter.doctor(box.home);
    expect(report.checks.find((c) => c.name === "daemon")).toMatchObject({
      ok: false,
      fix: "agent-vault daemon run",
    });
    expect(report.checks.find((c) => c.name === "hooks")?.ok).toBe(true);
    expect(report.checks.find((c) => c.name === "probe")?.ok).toBe(true);
  });

  test("a config.toml that does not parse is reported, not thrown", async () => {
    const m = await installed();
    write(configFile(), "= =");
    const report = await m.adapter.doctor(box.home);
    expect(report.ok).toBe(false);
    expect(report.checks.find((c) => c.name === "config")?.detail).toContain("config.toml");
  });
});

describe("prompt-submit hook", () => {
  test("a prompt with 2 keys blocks with exactly {decision, reason}, naming both refs", async () => {
    const m = make();
    const out = await m.adapter.handleHook(
      "prompt-submit",
      promptInput(`use ${PAT} and ${OPENAI}`),
    );
    const stored = await secrets();
    expect(stored).toHaveLength(2);
    for (const s of stored) expect(s.tags).toEqual([EXPOSED_TAG]);
    expect(out).toEqual({
      decision: "block",
      reason: expect.stringMatching(/^Stored as \S+, \S+\. Re-send using vault:\/\/\S+\.$/),
    });
    expect(Object.keys(out as object)).toEqual(["decision", "reason"]);
    const reason = (out as { reason: string }).reason;
    for (const s of stored) expect(reason).toContain(s.name);
    expect(JSON.stringify(out)).not.toContain(PAT);
    expect(JSON.stringify(out)).not.toContain(OPENAI);
  });

  test("a prompt with no key is allowed (null), and the daemon is never contacted", async () => {
    const m = make();
    expect(
      await m.adapter.handleHook("prompt-submit", promptInput("fix the failing test")),
    ).toBeNull();
    expect(m.connects()).toBe(0);
    expect(await secrets()).toEqual([]);
  });

  test("input that is not a Codex prompt event, and an unknown event, are allowed", async () => {
    const m = make();
    for (const input of [null, "text", {}, { prompt: 5 }, []]) {
      expect(await m.adapter.handleHook("prompt-submit", input)).toBeNull();
    }
    expect(await m.adapter.handleHook("nonsense", promptInput(PAT))).toBeNull();
    expect(await secrets()).toEqual([]);
  });

  test("with the daemon unreachable, a key still blocks, with the init hint", async () => {
    const m = make({ client: () => Promise.reject(new Error("connect ECONNREFUSED")) });
    const out = await m.adapter.handleHook("prompt-submit", promptInput(`k ${PAT}`));
    expect(out).toEqual({ decision: "block", reason: heldBackReason("codex") });
    expect(m.logs.join("\n")).not.toContain(PAT);
  });

  test("--probe blocks without storing or contacting the daemon", async () => {
    const m = make();
    const out = await m.adapter.handleHook("prompt-submit", promptInput(`k ${PAT}`), {
      probe: true,
    });
    expect(out).toMatchObject({ decision: "block" });
    expect(m.connects()).toBe(0);
    expect(await secrets()).toEqual([]);
  });

  test("history.jsonl and the rollout (which does not exist yet) are queued, then scrubbed at SessionStart", async () => {
    const m = make();
    expect(fs.existsSync(path.dirname(rollout()))).toBe(false);
    const out = await m.adapter.handleHook("prompt-submit", promptInput(`k ${PAT}`));
    expect(out).toMatchObject({ decision: "block" });

    // What Codex writes afterwards: the TUI's history line (S3), and the rollout.
    write(historyFile(), `${JSON.stringify({ session_id: "s1", ts: 1, text: `k ${PAT}` })}\n`);
    write(rollout(), `${JSON.stringify({ type: "response_item", content: `k ${PAT}` })}\n`);

    await m.adapter.handleHook("scrub", {
      session_id: "s2",
      transcript_path: rollout(),
      cwd: box.cwd,
      hook_event_name: "SessionStart",
      model: "gpt-x",
      permission_mode: "default",
      source: "startup",
    });
    for (const file of [historyFile(), rollout()]) {
      expect(read(file)).not.toContain(PAT);
      expect(read(file)).toContain("vault://");
    }
  });

  test("historyFiles: history.jsonl plus the rollout, under CODEX_HOME", () => {
    const m = make();
    expect(m.adapter.historyFiles(box.home)).toEqual([historyFile()]);
    expect(m.adapter.historyFiles(box.home, promptInput("x"))).toEqual([historyFile(), rollout()]);
    expect(m.adapter.historyFiles(box.home, { transcript_path: 5 })).toEqual([historyFile()]);
  });

  test("scrub with the daemon down returns null and does not throw", async () => {
    const m = make({ client: () => Promise.reject(new Error("down")) });
    expect(await m.adapter.handleHook("scrub", { hook_event_name: "SessionStart" })).toBeNull();
  });
});
