import fs from "node:fs";
import path from "node:path";
import type { SecretMeta } from "@agent-vault/core";
import { connect } from "@agent-vault/daemon";
import { detectSecrets } from "@agent-vault/detect";
import { ipcEndpoint } from "@agent-vault/platform";
import { parse as parseJsonc } from "jsonc-parser";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakes } from "../../detect/test/fixtures/fake-keys.js";
import {
  AdapterError,
  CLAUDE_HOOK_MARKER,
  type ClaudeRunner,
  createClaudeCodeAdapter,
  EXPOSED_TAG,
  findHooks,
  type HookClient,
  handlePromptSubmit,
  handleScrub,
  heldBackReason,
  type ProbeRunner,
  quoteArg,
  quoteCommand,
  splitCommand,
  tagFirst,
  versionManagerOf,
} from "../src/index.js";
import { useBox } from "./helpers.js";

const box = useBox();

const PAT = fakes.githubPat();
const OPENAI = fakes.openai();

beforeEach(() => {
  // The sandbox rule: the daemon judges "under home" by os.homedir(); nothing here may reach the
  // real home or the real ~/.claude.
  vi.stubEnv("HOME", box.home);
  vi.stubEnv("USERPROFILE", box.home);
});
afterEach(() => vi.unstubAllEnvs());

const read = (file: string): string => fs.readFileSync(file, "utf8");
const write = (file: string, text: string): string => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
};
const settingsFile = () => path.join(box.home, ".claude", "settings.json");
const globalFile = () => path.join(box.home, ".claude.json");
const transcript = () => path.join(box.home, ".claude", "projects", "proj", "s1.jsonl");
const backups = (): string[] =>
  fs.existsSync(box.paths.backupsDir) ? fs.readdirSync(box.paths.backupsDir) : [];

const secrets = async (): Promise<SecretMeta[]> =>
  (await box.client.call<SecretMeta[]>("secret.list")).sort((a, b) => a.name.localeCompare(b.name));

type Made = {
  adapter: ReturnType<typeof createClaudeCodeAdapter>;
  runClaude: ReturnType<typeof vi.fn<ClaudeRunner>>;
  runProbe: ReturnType<typeof vi.fn<ProbeRunner>>;
  connects: () => number;
  logs: string[];
  command: string[];
};

/** An adapter over the box's daemon. `claude` is a stub (code null: not installed). */
function make(
  extra: {
    env?: NodeJS.ProcessEnv;
    client?: () => Promise<HookClient>;
    claudeCode?: number | null;
    command?: string[];
    deadlineMs?: number;
  } = {},
): Made {
  const main = write(path.join(box.dir, "bin", "main.js"), "// stands in for the CLI\n");
  const command = extra.command ?? [process.execPath, main];
  let n = 0;
  const logs: string[] = [];
  const runClaude = vi.fn<ClaudeRunner>(async () => ({ code: extra.claudeCode ?? null }));
  const runProbe = vi.fn<ProbeRunner>(async () => ({
    code: 0,
    stdout: JSON.stringify({ decision: "block", reason: "probe" }),
  }));
  const adapter = createClaudeCodeAdapter({
    command,
    home: box.home,
    env: extra.env ?? {},
    backupsDir: box.paths.backupsDir,
    stateFile: path.join(box.dir, "state", "claude-code-state.json"),
    ...(extra.deadlineMs !== undefined && { deadlineMs: extra.deadlineMs }),
    runClaude,
    runProbe,
    client:
      extra.client ??
      (async () => {
        n++;
        return connect(ipcEndpoint(box.paths));
      }),
    log: (m) => logs.push(m),
  });
  return { adapter, runClaude, runProbe, connects: () => n, logs, command };
}

const promptInput = (prompt: string, extra: Record<string, unknown> = {}) => ({
  session_id: "s1",
  transcript_path: transcript(),
  cwd: box.cwd,
  prompt_id: "p1",
  permission_mode: "default",
  hook_event_name: "UserPromptSubmit",
  prompt,
  ...extra,
});

describe("prompt-submit hook", () => {
  test("a prompt with 2 keys blocks once, names both refs, and stores both as exposed-locally", async () => {
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
      reason: expect.stringContaining("Stored as "),
      hookSpecificOutput: { hookEventName: "UserPromptSubmit", suppressOriginalPrompt: true },
    });
    const reason = (out as { reason: string }).reason;
    for (const s of stored) expect(reason).toContain(s.name);
    expect(reason).toMatch(/^Stored as \S+, \S+\. Re-send using vault:\/\/\S+\.$/);
    // The exact key order of the S3 block shape.
    expect(Object.keys(out as object)).toEqual(["decision", "reason", "hookSpecificOutput"]);
    // The output carries no key.
    expect(JSON.stringify(out)).not.toContain(PAT);
    expect(JSON.stringify(out)).not.toContain(OPENAI);
  });

  test("a prompt with no key is allowed, and the daemon is never contacted", async () => {
    const m = make();
    const out = await m.adapter.handleHook("prompt-submit", promptInput("fix the failing test"));
    expect(out).toBeNull();
    expect(m.connects()).toBe(0);
    expect(await secrets()).toEqual([]);

    const client = vi.fn<() => Promise<HookClient>>();
    const decision = await handlePromptSubmit({
      harness: "claude-code",
      prompt: "nothing to see",
      historyFiles: [],
      client,
    });
    expect(decision).toEqual({ block: false });
    expect(client).not.toHaveBeenCalled();
  });

  test("with the daemon unreachable, a key still blocks, with the init hint", async () => {
    const m = make({ client: () => Promise.reject(new Error("connect ECONNREFUSED")) });
    const out = await m.adapter.handleHook("prompt-submit", promptInput(`k ${PAT}`));
    expect(out).toMatchObject({
      decision: "block",
      reason: "Key held back from the model. Run: agent-vault doctor claude-code",
      hookSpecificOutput: { suppressOriginalPrompt: true },
    });
    expect(heldBackReason("claude-code")).toBe((out as { reason: string }).reason);
    expect(m.logs.join("\n")).not.toContain(PAT);
  });

  test("a store that fails halfway still blocks, closes the connection, and says nothing is stored", async () => {
    let puts = 0;
    const close = vi.fn();
    const client: HookClient = {
      close,
      call: async (method) => {
        if (method === "secret.put" && ++puts === 2) throw new Error("disk full");
        return { name: `n${puts}` } as never;
      },
    };
    const decision = await handlePromptSubmit({
      harness: "claude-code",
      prompt: `${PAT} ${OPENAI}`,
      historyFiles: [],
      client: async () => client,
    });
    expect(decision).toMatchObject({ block: true, reason: heldBackReason("claude-code") });
    expect(close).toHaveBeenCalledOnce();
  });

  test("the same key pasted twice is stored once", async () => {
    const m = make();
    await m.adapter.handleHook("prompt-submit", promptInput(`${PAT}\n${PAT}`));
    expect(await secrets()).toHaveLength(1);
  });

  test("a transcript that does not exist yet (its directory neither) is queued and scrubbed later", async () => {
    const m = make();
    const history = path.join(box.home, ".claude", "history.jsonl");
    expect(fs.existsSync(path.dirname(transcript()))).toBe(false);

    const out = await m.adapter.handleHook("prompt-submit", promptInput(`k ${PAT}`));
    expect(out).toMatchObject({ decision: "block" });

    // Claude writes the transcript and the history after the hook returned.
    const line = (text: string) =>
      `${JSON.stringify({ type: "queue-operation", content: text })}\n`;
    write(transcript(), line(`k ${PAT}`) + line("harmless"));
    write(history, line(`k ${PAT}`));
    await m.adapter.handleHook("scrub", { hook_event_name: "SessionEnd", session_id: "s1" });

    const [secret] = await secrets();
    for (const file of [transcript(), history]) {
      expect(read(file)).not.toContain(PAT);
      expect(read(file)).toContain(`vault://${secret?.name}`);
    }
    expect(read(transcript())).toContain("harmless");
    // Valid JSON lines after the rewrite.
    for (const l of read(transcript()).trim().split("\n")) JSON.parse(l);
  });

  test("a transcript outside the home directory is dropped; the block and the history survive", async () => {
    const m = make();
    const outside = path.join(box.dir, "elsewhere", "t.jsonl");
    const out = await m.adapter.handleHook(
      "prompt-submit",
      promptInput(`k ${PAT}`, { transcript_path: outside }),
    );
    expect(out).toMatchObject({ decision: "block" });
    expect(await secrets()).toHaveLength(1);

    const history = write(path.join(box.home, ".claude", "history.jsonl"), `${PAT}\n`);
    await m.adapter.handleHook("scrub", {});
    expect(read(history)).not.toContain(PAT);
  });

  test("--probe blocks a prompt with a key, stores nothing and never contacts the daemon", async () => {
    const m = make();
    const out = await m.adapter.handleHook("prompt-submit", promptInput(`k ${PAT}`), {
      probe: true,
    });
    expect(out).toMatchObject({ decision: "block" });
    expect(m.connects()).toBe(0);
    expect(await secrets()).toEqual([]);
    expect(
      await m.adapter.handleHook("prompt-submit", promptInput("hi"), { probe: true }),
    ).toBeNull();
  });

  test("input that is not a prompt event is allowed", async () => {
    const m = make();
    for (const input of [null, "text", 42, [], {}, { prompt: 7 }]) {
      expect(await m.adapter.handleHook("prompt-submit", input)).toBeNull();
    }
    expect(await m.adapter.handleHook("something-else", promptInput(PAT))).toBeNull();
    expect(m.connects()).toBe(0);
  });

  test("historyFiles: the history, plus the transcript the input names", () => {
    const m = make();
    const history = path.join(box.home, ".claude", "history.jsonl");
    expect(m.adapter.historyFiles(box.home)).toEqual([history]);
    expect(m.adapter.historyFiles(box.home, promptInput("x"))).toEqual([history, transcript()]);
    const moved = make({ env: { CLAUDE_CONFIG_DIR: path.join(box.dir, "cfg") } });
    expect(moved.adapter.historyFiles(box.home)).toEqual([
      path.join(box.dir, "cfg", "history.jsonl"),
    ]);
  });
});

describe("prompt-submit deadline", () => {
  const input = () => ({ prompt: `k ${PAT}`, harness: "claude-code" as const, historyFiles: [] });

  test("a secret.put that never answers still ends in a block, within the deadline", async () => {
    const close = vi.fn();
    const timeouts: (number | undefined)[] = [];
    const client: HookClient = {
      close,
      call: (_method, _params, opts) => {
        timeouts.push(opts?.timeoutMs);
        return new Promise<never>(() => {});
      },
    };
    const started = Date.now();
    const decision = await handlePromptSubmit({
      ...input(),
      client: async () => client,
      deadlineMs: 150,
    });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(decision).toEqual({ block: true, reason: heldBackReason("claude-code"), names: [] });
    expect(close).toHaveBeenCalledOnce();
    // Each call is bounded by what is left of the deadline.
    expect(timeouts).toHaveLength(1);
    expect(timeouts[0]).toBeGreaterThan(0);
    expect(timeouts[0]).toBeLessThanOrEqual(150);
  });

  test("a connect that never answers blocks too, and a late connection is closed", async () => {
    const close = vi.fn();
    let release!: (c: HookClient) => void;
    const pending = new Promise<HookClient>((r) => {
      release = r;
    });
    const decision = await handlePromptSubmit({
      ...input(),
      client: () => pending,
      deadlineMs: 100,
    });
    expect(decision).toMatchObject({ block: true, reason: heldBackReason("claude-code") });
    const call = vi.fn();
    release({ call, close });
    await new Promise((r) => setTimeout(r, 20));
    expect(close).toHaveBeenCalledOnce();
    expect(call).not.toHaveBeenCalled(); // nothing is stored after the answer was given
  });

  test("through the adapter, with a short deadline", async () => {
    const m = make({ client: () => new Promise<never>(() => {}), deadlineMs: 100 });
    const out = await m.adapter.handleHook("prompt-submit", promptInput(`k ${PAT}`));
    expect(out).toMatchObject({
      decision: "block",
      reason: "Key held back from the model. Run: agent-vault doctor claude-code",
    });
  });

  test("blockOutput is the same JSON the hook prints", () => {
    expect(make().adapter.blockOutput("why")).toEqual({
      decision: "block",
      reason: "why",
      hookSpecificOutput: { hookEventName: "UserPromptSubmit", suppressOriginalPrompt: true },
    });
  });
});

describe("scrub hook", () => {
  test("gives up after its timeout, closes a late connection, and never throws", async () => {
    const logs: string[] = [];
    const close = vi.fn();
    let release!: (c: HookClient) => void;
    const slow = new Promise<HookClient>((r) => {
      release = r;
    });
    const started = Date.now();
    await handleScrub({
      harness: "claude-code",
      client: () => slow,
      timeoutMs: 50,
      log: (m) => logs.push(m),
    });
    expect(Date.now() - started).toBeLessThan(2000);
    expect(logs.join("\n")).toMatch(/did not finish/);
    release({ call: async () => ({}) as never, close });
    await new Promise((r) => setTimeout(r, 20));
    expect(close).toHaveBeenCalledOnce();
  });

  test("a daemon error is logged, not thrown", async () => {
    const logs: string[] = [];
    await handleScrub({
      harness: "claude-code",
      client: () => Promise.reject(new Error("no daemon")),
      log: (m) => logs.push(m),
    });
    expect(logs).toEqual(["agent-vault: scrub skipped: no daemon"]);
  });
});

describe("install and uninstall", () => {
  const MINE = {
    hooks: { UserPromptSubmit: [{ hooks: [{ type: "command", command: "echo mine" }] }] },
    model: "opus",
    permissions: { allow: ["Bash(ls:*)"] },
  };

  test("adds the 3 hooks beside the user's, keeps every other key, and backs the file up first", async () => {
    const original = `${JSON.stringify(MINE, null, 2)}\n`;
    write(settingsFile(), original);
    const m = make();
    const report = await m.adapter.install({ home: box.home });

    const settings = parseJsonc(read(settingsFile()));
    expect(settings.model).toBe("opus");
    expect(settings.permissions).toEqual(MINE.permissions);
    const prompt = settings.hooks.UserPromptSubmit;
    expect(prompt).toHaveLength(2);
    expect(prompt[0]).toEqual(MINE.hooks.UserPromptSubmit[0]); // theirs first, untouched
    expect(prompt[1].hooks[0]).toMatchObject({ type: "command", timeout: 30 });
    expect(prompt[1].hooks[0].command).toMatch(/ hook claude-code prompt-submit$/);
    for (const event of ["SessionEnd", "SessionStart"]) {
      expect(settings.hooks[event]).toHaveLength(1);
      expect(settings.hooks[event][0].hooks[0]).toMatchObject({ type: "command", timeout: 15 });
      expect(settings.hooks[event][0].hooks[0].command).toMatch(/ hook claude-code scrub$/);
    }
    // The command is absolute and runs node on the script.
    expect(splitCommand(prompt[1].hooks[0].command).slice(0, 2)).toEqual(
      m.command.map((c) => c.replaceAll("\\", "/")),
    );

    // One backup of the settings, holding the original bytes.
    const settingsBackups = report.backups.filter((b) => b.endsWith("settings.json"));
    expect(settingsBackups).toHaveLength(1);
    expect(read(settingsBackups[0] as string)).toBe(original);
    expect(backups().length).toBeGreaterThanOrEqual(1);
    expect(report.harness).toBe("claude-code");
    expect(report.files).toContain(settingsFile());
  });

  test("installing twice replaces our entries instead of duplicating them", async () => {
    write(settingsFile(), `${JSON.stringify(MINE, null, 2)}\n`);
    const m = make();
    await m.adapter.install({ home: box.home });
    const once = read(settingsFile());
    await m.adapter.install({ home: box.home });
    expect(read(settingsFile())).toBe(once);
    expect(findHooks(once, CLAUDE_HOOK_MARKER)).toHaveLength(3);
  });

  test("settings.json that install created is deleted by uninstall, unless the user added to it", async () => {
    const m = make();
    const report = await m.adapter.install({ home: box.home });
    expect(findHooks(read(settingsFile()), CLAUDE_HOOK_MARKER)).toHaveLength(3);
    expect(report.backups.filter((b) => b.endsWith("settings.json"))).toEqual([]);
    await m.adapter.uninstall(box.home);
    expect(fs.existsSync(settingsFile())).toBe(false);
    expect(fs.existsSync(globalFile())).toBe(false);

    await m.adapter.install({ home: box.home });
    fs.writeFileSync(settingsFile(), read(settingsFile()).replace(/^\{/, '{\n  "model": "opus",'));
    await m.adapter.uninstall(box.home);
    expect(parseJsonc(read(settingsFile()))).toEqual({ model: "opus" });
  });

  for (const blank of ["", "\n", "  \n\n", "\r\n"]) {
    test(`a settings.json that held only ${JSON.stringify(blank)} comes back unchanged`, async () => {
      write(settingsFile(), blank);
      const m = make();
      await m.adapter.install({ home: box.home });
      expect(findHooks(read(settingsFile()), CLAUDE_HOOK_MARKER)).toHaveLength(3);
      await m.adapter.uninstall(box.home);
      expect(read(settingsFile())).toBe(blank);
    });
  }

  for (const [name, original] of Object.entries({
    "an empty hooks object": '{\n  "model": "opus",\n  "hooks": {}\n}\n',
    "an empty event list": '{"hooks":{"UserPromptSubmit":[]}}',
    "a comment in an empty hooks object": '{\n  "hooks": {\n    // keep me\n  }\n}\n',
  })) {
    test(`uninstall leaves ${name} exactly as it was`, async () => {
      write(settingsFile(), original);
      const m = make();
      await m.adapter.install({ home: box.home });
      await m.adapter.uninstall(box.home);
      expect(read(settingsFile())).toBe(original);
    });
  }

  test("only entries with our exact command words are ours", async () => {
    const theirs = {
      hooks: {
        UserPromptSubmit: [
          { hooks: [{ type: "command", command: "mywrap hook claude-code notify" }] },
          { hooks: [{ type: "command", command: "/other/bin/tool hook claude-code scrub" }] },
        ],
      },
      apiKeyHelper: "/opt/bin/node /opt/other/main.js helper prod",
    };
    const original = `${JSON.stringify(theirs, null, 2)}\n`;
    write(settingsFile(), original);
    const m = make();
    await m.adapter.install({ home: box.home });
    expect(parseJsonc(read(settingsFile())).hooks.UserPromptSubmit).toHaveLength(3);
    await m.adapter.install({ home: box.home }); // replaces ours only
    expect(parseJsonc(read(settingsFile())).hooks.UserPromptSubmit).toHaveLength(3);
    await m.adapter.uninstall(box.home);
    expect(read(settingsFile())).toBe(original);
    const doctor = await m.adapter.doctor(box.home);
    expect(doctor.checks.find((c) => c.name === "hooks")?.ok).toBe(false);
  });

  test("a moved binary: the next install replaces the entries written for the old path", async () => {
    const m1 = make();
    await m1.adapter.install({ home: box.home });
    const moved = write(path.join(box.dir, "moved", "main.js"), "// moved\n");
    const m2 = make({ command: [process.execPath, moved] });
    await m2.adapter.install({ home: box.home });
    const entries = findHooks(read(settingsFile()), CLAUDE_HOOK_MARKER);
    expect(entries).toHaveLength(3);
    for (const e of entries) expect(e.command).toContain("moved");
    await m2.adapter.uninstall(box.home);
    expect(fs.existsSync(settingsFile())).toBe(false);
  });

  test("a Node under a version manager gets a warning at install and in doctor", async () => {
    expect(versionManagerOf("/Users/me/.nvm/versions/node/v24.0.0/bin/node")).toBe("nvm");
    expect(
      versionManagerOf("/Users/me/.local/share/fnm/node-versions/v24/installation/bin/node"),
    ).toBe("fnm");
    expect(versionManagerOf("/opt/homebrew/Cellar/node/25.1.0/bin/node")).toBe("Cellar");
    expect(versionManagerOf("C:\\Users\\me\\AppData\\Roaming\\nvm\\v24.0.0\\node.exe")).toBe("nvm");
    expect(versionManagerOf("/usr/local/bin/node")).toBeUndefined();
    expect(versionManagerOf("/home/me/.volta/tools/image/node/24/bin/node")).toBe("volta");
    expect(versionManagerOf("/home/me/.asdf/installs/nodejs/24/bin/node")).toBe("asdf");

    const node = write(path.join(box.dir, ".nvm", "versions", "node", "v24", "bin", "node"), "x");
    const main = path.join(box.dir, "bin", "main.js");
    const m = make({ command: [node, main] });
    const report = await m.adapter.install({ home: box.home });
    expect(report.warnings?.join("\n")).toMatch(/nvm.*silently disables/s);
    const doctor = await m.adapter.doctor(box.home);
    const hooks = doctor.checks.find((c) => c.name === "hooks");
    expect(hooks).toMatchObject({ ok: true, warning: expect.stringContaining("nvm") });
    expect(doctor.ok).toBe(true);

    const plain = await make({ command: ["/usr/local/bin/node", main] }).adapter.install({
      home: box.home,
    });
    expect(plain.warnings).toEqual([]);
  });

  const ORIGINALS: Record<string, string> = {
    pretty: `${JSON.stringify(MINE, null, 2)}\n`,
    "no trailing newline": JSON.stringify(MINE, null, 2),
    "four spaces": `${JSON.stringify(MINE, null, 4)}\n`,
    tabs: `${JSON.stringify(MINE, null, "\t")}\n`,
    "no hooks key": '{\n  "model": "opus"\n}\n',
    comments: '{\n  // my model\n  "model": "opus", // keep\n  "env": {}\n}\n',
    "empty object": "{}\n",
  };
  for (const [name, original] of Object.entries(ORIGINALS)) {
    test(`uninstall gives settings.json back byte for byte (${name})`, async () => {
      write(settingsFile(), original);
      const m = make();
      const report = await m.adapter.install({ home: box.home });
      expect(read(settingsFile())).not.toBe(original);
      await m.adapter.uninstall(box.home);
      expect(read(settingsFile())).toBe(original);
      expect(read(report.backups.find((b) => b.endsWith("settings.json")) as string)).toBe(
        original,
      );
    });
  }

  test("uninstall keeps what the user changed since install", async () => {
    write(settingsFile(), `${JSON.stringify(MINE, null, 2)}\n`);
    const m = make();
    await m.adapter.install({ home: box.home });
    const edited = setModel(read(settingsFile()));
    fs.writeFileSync(settingsFile(), edited);
    await m.adapter.uninstall(box.home);
    const after = parseJsonc(read(settingsFile()));
    expect(after.model).toBe("sonnet");
    expect(after.hooks).toEqual(MINE.hooks);
  });

  test("registers MCP with `claude mcp add --scope user` and leaves .claude.json to claude", async () => {
    const m = make({ claudeCode: 0 });
    const report = await m.adapter.install({ home: box.home });
    expect(m.runClaude).toHaveBeenCalledOnce();
    expect(m.runClaude).toHaveBeenCalledWith([
      "mcp",
      "add",
      "--scope",
      "user",
      "agent-vault",
      "--",
      ...m.command,
      "mcp",
    ]);
    expect(fs.existsSync(globalFile())).toBe(false);
    expect(report.notes.join("\n")).toMatch(/claude mcp add/);
  });

  test("without a claude binary, writes the entry into .claude.json and uninstall restores it", async () => {
    const original = `${JSON.stringify({ numStartups: 3, mcpServers: { git: { command: "x" } } }, null, 2)}\n`;
    write(globalFile(), original);
    const m = make(); // runClaude answers code null: not installed
    const report = await m.adapter.install({ home: box.home });

    const entry = parseJsonc(read(globalFile())).mcpServers["agent-vault"];
    expect(entry).toEqual({
      type: "stdio",
      command: m.command[0],
      args: [...m.command.slice(1), "mcp"],
    });
    expect(parseJsonc(read(globalFile())).mcpServers.git).toEqual({ command: "x" });
    const globalBackup = report.backups.find((b) => b.endsWith(".claude.json")) as string;
    expect(read(globalBackup)).toBe(original);

    await m.adapter.uninstall(box.home);
    expect(read(globalFile())).toBe(original);
    expect(m.runClaude).toHaveBeenCalledWith(["mcp", "remove", "--scope", "user", "agent-vault"]);
  });

  test("a failing `claude mcp add` falls back to the file", async () => {
    const m = make({ claudeCode: 1 });
    await m.adapter.install({ home: box.home });
    expect(parseJsonc(read(globalFile())).mcpServers["agent-vault"]).toBeTypeOf("object");
  });

  test("installing again does not register MCP twice", async () => {
    const m = make();
    await m.adapter.install({ home: box.home });
    const once = read(globalFile());
    m.runClaude.mockClear();
    await m.adapter.install({ home: box.home });
    expect(m.runClaude).not.toHaveBeenCalled();
    expect(read(globalFile())).toBe(once);
  });

  test("an MCP entry that points at an old install is updated in place, not duplicated", async () => {
    write(
      globalFile(),
      `${JSON.stringify({ mcpServers: { "agent-vault": { type: "stdio", command: "/old/agent-vault", args: ["mcp"] } } }, null, 2)}\n`,
    );
    const m = make();
    await m.adapter.install({ home: box.home });
    expect(m.runClaude).not.toHaveBeenCalled();
    expect(parseJsonc(read(globalFile())).mcpServers["agent-vault"]).toEqual({
      type: "stdio",
      command: m.command[0],
      args: [...m.command.slice(1), "mcp"],
    });
  });

  test("CLAUDE_CONFIG_DIR moves settings.json and .claude.json", async () => {
    const cfg = path.join(box.dir, "cfg");
    const m = make({ env: { CLAUDE_CONFIG_DIR: cfg } });
    await m.adapter.install({ home: box.home });
    expect(findHooks(read(path.join(cfg, "settings.json")), CLAUDE_HOOK_MARKER)).toHaveLength(3);
    expect(parseJsonc(read(path.join(cfg, ".claude.json"))).mcpServers["agent-vault"]).toBeTypeOf(
      "object",
    );
    expect(fs.existsSync(settingsFile())).toBe(false);
    expect(await m.adapter.detect(box.home)).toBe(true);
    await m.adapter.uninstall(box.home);
    expect(fs.existsSync(path.join(cfg, "settings.json"))).toBe(false);
  });

  test("detect: a home without Claude is not detected", async () => {
    expect(await make().adapter.detect(box.home)).toBe(false);
    write(settingsFile(), "{}\n");
    expect(await make().adapter.detect(box.home)).toBe(true);
  });

  test("a settings.json that is not JSON stops the install before anything is written", async () => {
    write(settingsFile(), '{ "model": ');
    const m = make();
    await expect(m.adapter.install({ home: box.home })).rejects.toThrow(AdapterError);
    expect(read(settingsFile())).toBe('{ "model": ');
    expect(backups()).toEqual([]);
    expect(m.runClaude).not.toHaveBeenCalled();
  });

  describe("--model-key", () => {
    const put = (name: string, tags: string[]) =>
      box.client.call("secret.put", {
        name,
        valueB64: Buffer.from("not-a-real-secret-value").toString("base64"),
        tags,
      });

    test("is refused for a secret without the helper tag, and nothing is changed", async () => {
      await put("anthropic/main", ["work"]);
      const m = make();
      await expect(
        m.adapter.install({ home: box.home, modelKey: "anthropic/main" }),
      ).rejects.toThrow("tag it first: agent-vault set anthropic/main --tag helper");
      expect(tagFirst("anthropic/main")).toBe(
        "tag it first: agent-vault set anthropic/main --tag helper",
      );
      expect(fs.existsSync(settingsFile())).toBe(false);
      expect(m.runClaude).not.toHaveBeenCalled();
    });

    test("is refused for a secret that does not exist", async () => {
      const m = make();
      await expect(m.adapter.install({ home: box.home, modelKey: "nope" })).rejects.toThrow(
        /tag it first/,
      );
      expect(fs.existsSync(settingsFile())).toBe(false);
    });

    test("sets apiKeyHelper for a helper-tagged secret, and uninstall removes only that", async () => {
      await put("anthropic/main", ["helper"]);
      const original = `${JSON.stringify(MINE, null, 2)}\n`;
      write(settingsFile(), original);
      const m = make();
      await m.adapter.install({ home: box.home, modelKey: "anthropic/main" });

      const helper = parseJsonc(read(settingsFile())).apiKeyHelper as string;
      expect(splitCommand(helper)).toEqual([
        ...m.command.map((c) => c.replaceAll("\\", "/")),
        "helper",
        "anthropic/main",
      ]);
      // Reinstalling without --model-key keeps it: it is ours.
      await m.adapter.install({ home: box.home });
      expect(parseJsonc(read(settingsFile())).apiKeyHelper).toBe(helper);

      await m.adapter.uninstall(box.home);
      expect(read(settingsFile())).toBe(original);
    });

    test("never replaces someone else's apiKeyHelper, and uninstall never removes it", async () => {
      await put("anthropic/main", ["helper"]);
      const theirs = `${JSON.stringify({ apiKeyHelper: "/usr/local/bin/their-helper" }, null, 2)}\n`;
      write(settingsFile(), theirs);
      const m = make();
      await expect(
        m.adapter.install({ home: box.home, modelKey: "anthropic/main" }),
      ).rejects.toThrow(/already sets apiKeyHelper/);
      expect(read(settingsFile())).toBe(theirs);

      await m.adapter.install({ home: box.home });
      await m.adapter.uninstall(box.home);
      expect(read(settingsFile())).toBe(theirs);
    });
  });
});

describe("doctor", () => {
  test("reports every check green in a sandbox", async () => {
    const m = make();
    await m.adapter.install({ home: box.home });
    const report = await m.adapter.doctor(box.home);
    expect(report.checks.map((c) => [c.name, c.ok])).toEqual([
      ["hooks", true],
      ["daemon", true],
      ["vault", true],
      ["mcp", true],
      ["probe", true],
      ["apiKeyHelper", true],
    ]);
    expect(report.ok).toBe(true);

    // The probe ran the installed prompt-submit command with --probe and a made-up key.
    expect(m.runProbe).toHaveBeenCalledOnce();
    const [command, stdin] = m.runProbe.mock.calls[0] as [string, string];
    expect(command).toMatch(/ hook claude-code prompt-submit --probe$/);
    const prompt = (JSON.parse(stdin) as { prompt: string }).prompt;
    expect(detectSecrets(prompt)).toHaveLength(1);
    expect(report.checks.map((c) => c.detail).join("\n")).not.toContain(
      detectSecrets(prompt)[0]?.value,
    );
  });

  test("is red, with the fix, when the hook entries are missing", async () => {
    const m = make();
    write(settingsFile(), '{\n  "model": "opus"\n}\n');
    const report = await m.adapter.doctor(box.home);
    expect(report.ok).toBe(false);
    const hooks = report.checks.find((c) => c.name === "hooks");
    expect(hooks).toMatchObject({ ok: false, fix: "agent-vault install claude-code" });
    expect(hooks?.detail).toContain("UserPromptSubmit");
    expect(report.checks.find((c) => c.name === "probe")).toMatchObject({ ok: false });
    expect(report.checks.find((c) => c.name === "mcp")).toMatchObject({
      ok: false,
      fix: "agent-vault install claude-code",
    });
    expect(m.runProbe).not.toHaveBeenCalled();
    // The green ones carry no fix.
    expect(report.checks.find((c) => c.name === "daemon")).not.toHaveProperty("fix");
  });

  test("is red when one of the three hooks is missing, or the binary is gone", async () => {
    const m = make();
    await m.adapter.install({ home: box.home });
    const text = read(settingsFile());
    const settings = parseJsonc(text);
    delete settings.hooks.SessionStart;
    fs.writeFileSync(settingsFile(), JSON.stringify(settings, null, 2));
    const missing = await m.adapter.doctor(box.home);
    expect(missing.checks.find((c) => c.name === "hooks")?.detail).toContain("SessionStart");

    fs.writeFileSync(settingsFile(), text);
    fs.rmSync(m.command[1] as string);
    const gone = await m.adapter.doctor(box.home);
    expect(gone.checks.find((c) => c.name === "hooks")).toMatchObject({
      ok: false,
      detail: expect.stringContaining("does not exist"),
    });
  });

  test("is red when the probe does not block, and when the daemon is down", async () => {
    const m = make({ client: () => Promise.reject(new Error("connect ECONNREFUSED")) });
    await m.adapter.install({ home: box.home }); // needs no daemon
    m.runProbe.mockResolvedValue({ code: 0, stdout: "" });
    const report = await m.adapter.doctor(box.home);
    expect(report.checks.find((c) => c.name === "daemon")).toMatchObject({
      ok: false,
      fix: "agent-vault daemon run",
    });
    expect(report.checks.find((c) => c.name === "probe")).toMatchObject({ ok: false });
    expect(report.ok).toBe(false);
  });

  test("checks that our apiKeyHelper's binary exists, and leaves someone else's alone", async () => {
    const m = make();
    write(settingsFile(), '{\n  "apiKeyHelper": "/usr/local/bin/their-helper"\n}\n');
    await m.adapter.install({ home: box.home });
    const theirs = await m.adapter.doctor(box.home);
    expect(theirs.checks.find((c) => c.name === "apiKeyHelper")).toMatchObject({ ok: true });
  });
});

describe("quoting", () => {
  test("POSIX words are quoted only when they need to be, and split back", () => {
    expect(quoteArg("/usr/bin/node", "linux")).toBe("/usr/bin/node");
    expect(quoteArg("/my dir/it's", "linux")).toBe("'/my dir/it'\\''s'");
    const argv = ["/my dir/node", "/a b/main.js", "hook", "x'y", ""];
    expect(splitCommand(quoteCommand(argv, "linux"))).toEqual(argv);
  });

  test("Windows words use forward slashes and double quotes", () => {
    expect(quoteArg("C:\\Program Files\\nodejs\\node.exe", "win32")).toBe(
      '"C:/Program Files/nodejs/node.exe"',
    );
    expect(quoteArg("D:\\a\\main.js", "win32")).toBe("D:/a/main.js");
    expect(splitCommand(quoteCommand(["C:\\Program Files\\node.exe", "x"], "win32"))).toEqual([
      "C:/Program Files/node.exe",
      "x",
    ]);
  });
});

function setModel(text: string): string {
  return text.replace('"model": "opus"', '"model": "sonnet"');
}
