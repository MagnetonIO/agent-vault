import fs from "node:fs";
import path from "node:path";
import { connect } from "@agent-vault/daemon";
import { ipcEndpoint } from "@agent-vault/platform";
import { parse as parseJsonc } from "jsonc-parser";
import { describe, expect, test } from "vitest";
import {
  AdapterError,
  createOpenCodeAdapter,
  type HookClient,
  OPENCODE_SCHEMA,
} from "../src/index.js";
import { useBox } from "./helpers.js";

const box = useBox();

const write = (file: string, text: string): string => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
};
const read = (file: string): string => fs.readFileSync(file, "utf8");
const backups = (): string[] =>
  fs.existsSync(box.paths.backupsDir) ? fs.readdirSync(box.paths.backupsDir) : [];

const stateFile = () => path.join(box.dir, "state", "opencode-state.json");

/** Where OpenCode looks when XDG_CONFIG_HOME is unset. */
const defaultDir = () => path.join(box.home, ".config", "opencode");
const jsonFile = (dir = defaultDir()) => path.join(dir, "opencode.json");
const jsoncFile = (dir = defaultDir()) => path.join(dir, "opencode.jsonc");

const PROMPT_LINE = "use agent-vault grab (no OpenCode prompt hook yet)";
const DB_LINE =
  "pasted text is stored in opencode.db, which agent-vault does not scrub; run agent-vault scan to find exposed keys";

/** The adapter over the box's daemon. The `opencode` binary is never involved. */
function make(
  extra: { env?: NodeJS.ProcessEnv; client?: () => Promise<HookClient>; command?: string[] } = {},
) {
  const logs: string[] = [];
  const main = write(path.join(box.dir, "bin", "main.js"), "// stands in for the CLI\n");
  const command = extra.command ?? [process.execPath, main];
  const adapter = createOpenCodeAdapter({
    command,
    env: extra.env ?? {},
    backupsDir: box.paths.backupsDir,
    stateFile: stateFile(),
    client: extra.client ?? (async () => connect(ipcEndpoint(box.paths))),
    log: (m) => logs.push(m),
  });
  return { adapter, command, logs };
}

const entryOf = (command: string[]) => ({
  type: "local",
  command: [...command, "mcp"],
  enabled: true,
});

const COMMENTED = `{
  // my opencode setup
  "$schema": "https://opencode.ai/config.json",
  "theme": "tokyonight", // dark one
  /* providers stay as they are */
  "mcp": {
    "other": { "type": "remote", "url": "https://example.test/mcp" },
  },
}
`;

/** Entries under our name that agent-vault did not write. */
const FOREIGN: [string, unknown][] = [
  ["a remote server", { type: "remote", url: "https://my.example/mcp" }],
  ["a local server with another command", { type: "local", command: ["npx", "my-server"] }],
  ["a local command that does not end in mcp", { type: "local", command: ["/usr/bin/x", "serve"] }],
  ["a relative command", { type: "local", command: ["./bin/x", "mcp"], enabled: true }],
];
const foreignFile = (entry: unknown) =>
  `{\n  // mine\n  "mcp": {\n    "agent-vault": ${JSON.stringify(entry)}\n  }\n}\n`;

describe("an agent-vault entry that is not ours", () => {
  for (const [label, entry] of FOREIGN) {
    test(`install refuses ${label} and writes nothing`, async () => {
      const { adapter } = make();
      const text = foreignFile(entry);
      write(jsonFile(), text);
      await expect(adapter.install({ home: box.home })).rejects.toThrow(
        'opencode.json already has an "agent-vault" MCP entry that agent-vault did not write; remove or rename it, then run install again',
      );
      expect(read(jsonFile())).toBe(text);
      expect(backups()).toEqual([]);
    });

    test(`uninstall leaves ${label} alone, says so, and does not throw`, async () => {
      const { adapter, logs } = make();
      const text = foreignFile(entry);
      write(jsonFile(), text);
      await adapter.uninstall(box.home);
      expect(read(jsonFile())).toBe(text);
      expect(backups()).toEqual([]);
      expect(logs).toHaveLength(1);
      expect(logs[0]).toContain("did not write");
    });

    test(`doctor reports ${label} as red`, async () => {
      const { adapter } = make();
      write(jsonFile(), foreignFile(entry));
      const report = await adapter.doctor(box.home);
      const mcp = report.checks.find((c) => c.name === "mcp");
      expect(mcp).toMatchObject({ ok: false });
      expect(mcp?.detail).toContain("did not write; remove or rename it");
      expect(report.ok).toBe(false);
    });
  }

  test("a foreign entry in opencode.jsonc is caught too", async () => {
    const { adapter } = make();
    write(jsonFile(), "{}\n");
    write(jsoncFile(), foreignFile(FOREIGN[0]?.[1]));
    await expect(adapter.install({ home: box.home })).rejects.toThrow(
      /opencode\.jsonc already has/,
    );
    expect(read(jsonFile())).toBe("{}\n");
  });

  test("our own entry from another install location is replaced in place", async () => {
    const { adapter, command } = make();
    write(
      jsonFile(),
      `{\n  "mcp": {\n    "agent-vault": { "type": "local", "command": ["/old/place/agent-vault", "mcp"], "enabled": true }\n  }\n}\n`,
    );
    await adapter.install({ home: box.home });
    const root = parseJsonc(read(jsonFile())) as { mcp: Record<string, unknown> };
    expect(root.mcp["agent-vault"]).toEqual(entryOf(command));
    await adapter.uninstall(box.home);
    // No record says install made `mcp`, so it stays (empty).
    expect(parseJsonc(read(jsonFile()))).toEqual({ mcp: {} });
  });

  test("the bare name agent-vault counts as ours", async () => {
    const { adapter, command } = make();
    write(
      jsonFile(),
      JSON.stringify({
        mcp: { "agent-vault": { type: "local", command: ["agent-vault", "mcp"] } },
      }),
    );
    await adapter.install({ home: box.home });
    const root = parseJsonc(read(jsonFile())) as { mcp: Record<string, unknown> };
    expect(root.mcp["agent-vault"]).toEqual(entryOf(command));
  });
});

describe("install", () => {
  test("keeps comments and formatting and adds the MCP entry", async () => {
    const { adapter, command } = make();
    write(jsonFile(), COMMENTED);

    const report = await adapter.install({ home: box.home });

    const after = read(jsonFile());
    for (const keep of [
      "// my opencode setup",
      "// dark one",
      "/* providers stay as they are */",
      `"theme": "tokyonight"`,
      `"other": { "type": "remote", "url": "https://example.test/mcp" }`,
    ]) {
      expect(after).toContain(keep);
    }
    const root = parseJsonc(after) as { mcp: Record<string, unknown> };
    expect(root.mcp["agent-vault"]).toEqual(entryOf(command));
    expect(Object.keys(root.mcp)).toEqual(["other", "agent-vault"]);
    expect(report).toMatchObject({ harness: "opencode", files: [jsonFile()] });
    expect(report.backups).toHaveLength(1);
    expect(read(report.backups[0] as string)).toBe(COMMENTED);
  });

  test("the entry uses absolute words and `enabled: true`", async () => {
    const { adapter } = make();
    await adapter.install({ home: box.home });
    const root = parseJsonc(read(jsonFile())) as {
      mcp: { "agent-vault": { command: string[]; enabled: boolean; type: string } };
    };
    const entry = root.mcp["agent-vault"];
    expect(entry.type).toBe("local");
    expect(entry.enabled).toBe(true);
    expect(entry.command.at(-1)).toBe("mcp");
    expect(path.isAbsolute(entry.command[0] as string)).toBe(true);
  });

  test("a second install changes nothing and makes no backup", async () => {
    const { adapter } = make();
    write(jsonFile(), COMMENTED);
    await adapter.install({ home: box.home });
    const once = read(jsonFile());
    const backupsAfterFirst = backups().length;

    const report = await adapter.install({ home: box.home });

    expect(read(jsonFile())).toBe(once);
    expect(backups()).toHaveLength(backupsAfterFirst);
    expect(report.backups).toEqual([]);
    expect(report.files).toEqual([]);
    expect(report.notes.join("\n")).toMatch(/already/);
  });

  test("a stale entry is replaced in place, not duplicated", async () => {
    const { adapter, command } = make();
    write(
      jsonFile(),
      `{\n  "mcp": {\n    "agent-vault": { "type": "local", "command": ["/old/agent-vault", "mcp"], "enabled": false },\n    "z": { "type": "remote", "url": "https://z.test" }\n  }\n}\n`,
    );
    await adapter.install({ home: box.home });
    const root = parseJsonc(read(jsonFile())) as { mcp: Record<string, unknown> };
    expect(Object.keys(root.mcp)).toEqual(["agent-vault", "z"]);
    expect(root.mcp["agent-vault"]).toEqual(entryOf(command));
  });

  test("a missing file is created with $schema and the entry", async () => {
    const { adapter, command } = make();
    expect(fs.existsSync(defaultDir())).toBe(false);

    const report = await adapter.install({ home: box.home });

    const root = parseJsonc(read(jsonFile())) as Record<string, unknown>;
    expect(root).toEqual({ $schema: OPENCODE_SCHEMA, mcp: { "agent-vault": entryOf(command) } });
    expect(report.backups).toEqual([]);
    expect(report.files).toEqual([jsonFile()]);
  });

  test("an empty file is treated as {}", async () => {
    const { adapter, command } = make();
    write(jsonFile(), "");
    await adapter.install({ home: box.home });
    expect(parseJsonc(read(jsonFile()))).toEqual({ mcp: { "agent-vault": entryOf(command) } });
  });

  test("XDG_CONFIG_HOME wins over ~/.config", async () => {
    const xdg = path.join(box.dir, "xdg-config");
    const { adapter } = make({ env: { XDG_CONFIG_HOME: xdg } });
    await adapter.install({ home: box.home });
    expect(fs.existsSync(jsonFile(path.join(xdg, "opencode")))).toBe(true);
    expect(fs.existsSync(defaultDir())).toBe(false);
  });

  test("an opencode.jsonc is edited in place and no opencode.json is created", async () => {
    const { adapter, command } = make();
    write(jsoncFile(), COMMENTED);
    const report = await adapter.install({ home: box.home });
    expect(fs.existsSync(jsonFile())).toBe(false);
    expect(report.files).toEqual([jsoncFile()]);
    expect(read(jsoncFile())).toContain("// my opencode setup");
    const root = parseJsonc(read(jsoncFile())) as { mcp: Record<string, unknown> };
    expect(root.mcp["agent-vault"]).toEqual(entryOf(command));
  });

  test("opencode.json is preferred when both files exist", async () => {
    const { adapter } = make();
    write(jsonFile(), "{}\n");
    write(jsoncFile(), "{}\n");
    const report = await adapter.install({ home: box.home });
    expect(report.files).toEqual([jsonFile()]);
    expect(read(jsoncFile())).toBe("{}\n");
  });

  test("refuses before writing anything", async () => {
    const { adapter } = make({ command: ["agent-vault"] });
    await expect(adapter.install({ home: box.home })).rejects.toThrow(AdapterError);
    expect(fs.existsSync(defaultDir())).toBe(false);

    const ok = make();
    const cases: [string, RegExp][] = [
      ["{ not json", /not usable/],
      ["[]", /not usable/],
      [`{ "mcp": [] }`, /"mcp" is not an object/],
      [`{ "mcp": { "agent-vault": 3 } }`, /not an object/],
    ];
    for (const [text, why] of cases) {
      write(jsonFile(), text);
      await expect(ok.adapter.install({ home: box.home })).rejects.toThrow(why);
      expect(read(jsonFile()), text).toBe(text);
    }
    expect(backups()).toEqual([]);
  });

  test("a --model-key is refused: OpenCode has no key helper", async () => {
    const { adapter } = make();
    await expect(adapter.install({ home: box.home, modelKey: "x/y" })).rejects.toThrow(
      /model-key.*claude-code/,
    );
    expect(fs.existsSync(defaultDir())).toBe(false);
  });
});

describe("uninstall", () => {
  const files = [
    ["comments and a trailing comma", COMMENTED],
    ["an empty mcp-less object", "{}\n"],
    [
      "tabs and CRLF",
      `{\r\n\t"theme": "x",\r\n\t"mcp": {\r\n\t\t"other": { "type": "remote", "url": "u" }\r\n\t}\r\n}\r\n`,
    ],
    ["one line", `{"theme":"x"}`],
    ["a lone key and no final newline", `{\n  "theme": "x"\n}`],
  ] as const;

  for (const [label, original] of files) {
    test(`is byte-identical after install: ${label}`, async () => {
      const { adapter } = make();
      write(jsonFile(), original);
      await adapter.install({ home: box.home });
      expect(read(jsonFile())).not.toBe(original);

      await adapter.uninstall(box.home);

      expect(read(jsonFile())).toBe(original);
    });
  }

  test("is byte-identical for an opencode.jsonc", async () => {
    const { adapter } = make();
    write(jsoncFile(), COMMENTED);
    await adapter.install({ home: box.home });
    await adapter.uninstall(box.home);
    expect(read(jsoncFile())).toBe(COMMENTED);
  });

  test("deletes a file that install created, after backing it up", async () => {
    const { adapter } = make();
    await adapter.install({ home: box.home });
    expect(fs.existsSync(jsonFile())).toBe(true);
    const installed = read(jsonFile());

    await adapter.uninstall(box.home);

    expect(fs.existsSync(jsonFile())).toBe(false);
    const saved = backups();
    expect(saved).toHaveLength(1);
    expect(read(path.join(box.paths.backupsDir, saved[0] as string))).toBe(installed);
  });

  test("keeps a created file the user has since changed", async () => {
    const { adapter } = make();
    await adapter.install({ home: box.home });
    const edited = read(jsonFile()).replace("{", `{\n  "theme": "mine",`);
    write(jsonFile(), edited);

    await adapter.uninstall(box.home);

    const root = parseJsonc(read(jsonFile())) as Record<string, unknown>;
    expect(root).toEqual({ $schema: OPENCODE_SCHEMA, theme: "mine" });
  });

  test("removes exactly our entry and leaves the user's other servers", async () => {
    const { adapter } = make();
    write(jsonFile(), COMMENTED);
    await adapter.install({ home: box.home });
    // The user adds a server after install.
    const withMore = read(jsonFile()).replace(
      `"other":`,
      `"later": { "type": "remote", "url": "https://later.test" },\n    "other":`,
    );
    write(jsonFile(), withMore);

    await adapter.uninstall(box.home);

    const root = parseJsonc(read(jsonFile())) as { mcp: Record<string, unknown> };
    expect(Object.keys(root.mcp)).toEqual(["later", "other"]);
    expect(read(jsonFile())).toContain("// my opencode setup");
  });

  test("an empty mcp object the user had comes back as it was", async () => {
    const { adapter } = make();
    for (const original of [
      `{\n  "mcp": {}\n}\n`,
      `{ "theme": "x", "mcp": {} }`,
      `{\n  "mcp": {\n    // add servers here\n  }\n}\n`,
    ]) {
      write(jsonFile(), original);
      await adapter.install({ home: box.home });
      expect(read(jsonFile()), original).not.toBe(original);
      await adapter.uninstall(box.home);
      expect(read(jsonFile()), original).toBe(original);
    }
  });

  test("a file that held only white space gets that white space back", async () => {
    const { adapter } = make();
    for (const original of ["", "\n", "  \n\n", "\t\r\n"]) {
      write(jsonFile(), original);
      await adapter.install({ home: box.home });
      expect(parseJsonc(read(jsonFile()))).toHaveProperty("mcp");
      await adapter.uninstall(box.home);
      expect(read(jsonFile()), JSON.stringify(original)).toBe(original);
    }
  });

  test("the mcp object install made goes with the entry; one the user had stays", async () => {
    const { adapter } = make();
    write(jsonFile(), `{ "theme": "x" }\n`);
    await adapter.install({ home: box.home });
    await adapter.uninstall(box.home);
    expect(read(jsonFile())).toBe(`{ "theme": "x" }\n`);

    write(jsonFile(), `{ "mcp": { "a": { "type": "remote", "url": "u" } } }\n`);
    await adapter.install({ home: box.home });
    await adapter.uninstall(box.home);
    expect(read(jsonFile())).toBe(`{ "mcp": { "a": { "type": "remote", "url": "u" } } }\n`);
  });

  test("a file that merely looks like the one install writes is not deleted", async () => {
    const { adapter } = make();
    // The user's own file, byte for byte what a fresh install would have made after uninstall.
    const lookalike = `{\n  "$schema": "${OPENCODE_SCHEMA}"\n}\n`;
    write(jsonFile(), lookalike);
    await adapter.install({ home: box.home });
    await adapter.uninstall(box.home);
    expect(read(jsonFile())).toBe(lookalike);
  });

  test("the record is dropped on uninstall, and a later install starts fresh", async () => {
    const { adapter } = make();
    await adapter.install({ home: box.home });
    expect(fs.existsSync(stateFile())).toBe(true);
    await adapter.uninstall(box.home);
    expect(fs.existsSync(stateFile())).toBe(false);
    write(jsonFile(), "{}\n");
    await adapter.install({ home: box.home });
    await adapter.uninstall(box.home);
    expect(read(jsonFile())).toBe("{}\n");
  });

  test("with nothing installed it does nothing: no file, no backup", async () => {
    const { adapter } = make();
    await adapter.uninstall(box.home);
    expect(fs.existsSync(defaultDir())).toBe(false);
    write(jsonFile(), COMMENTED);
    await adapter.uninstall(box.home);
    expect(read(jsonFile())).toBe(COMMENTED);
    expect(backups()).toEqual([]);
  });

  test("a file that is not JSON is reported, not touched", async () => {
    const { adapter } = make();
    write(jsonFile(), "{ nope");
    await expect(adapter.uninstall(box.home)).rejects.toThrow(AdapterError);
    expect(read(jsonFile())).toBe("{ nope");
  });
});

describe("doctor", () => {
  const line = (r: Awaited<ReturnType<ReturnType<typeof make>["adapter"]["doctor"]>>, n: string) =>
    r.checks.find((c) => c.name === n);

  test("after install: mcp, daemon and vault pass; prompt capture is informational", async () => {
    const { adapter } = make();
    await adapter.install({ home: box.home });

    const report = await adapter.doctor(box.home);

    expect(report.harness).toBe("opencode");
    expect(report.ok).toBe(true);
    expect(report.checks.map((c) => c.name)).toEqual([
      "mcp",
      "daemon",
      "vault",
      "prompt capture",
      "note",
    ]);
    expect(report.checks.every((c) => c.ok)).toBe(true);
    expect(line(report, "prompt capture")).toMatchObject({ info: true, detail: PROMPT_LINE });
    expect(line(report, "note")).toMatchObject({ info: true, detail: DB_LINE });
  });

  test("the two informational lines do not depend on the install state", async () => {
    const { adapter } = make();
    const report = await adapter.doctor(box.home);
    expect(line(report, "prompt capture")?.detail).toBe(PROMPT_LINE);
    expect(line(report, "note")?.detail).toBe(DB_LINE);
  });

  test("before install: mcp fails with the fix, and the report is not ok", async () => {
    const { adapter } = make();
    const report = await adapter.doctor(box.home);
    expect(report.ok).toBe(false);
    expect(line(report, "mcp")).toMatchObject({
      ok: false,
      fix: "agent-vault install opencode",
    });
    expect(fs.existsSync(defaultDir())).toBe(false);
  });

  test("mcp fails when the binary it runs is gone", async () => {
    const { adapter, command } = make();
    await adapter.install({ home: box.home });
    fs.rmSync(command[1] as string);

    const report = await adapter.doctor(box.home);

    expect(report.ok).toBe(false);
    expect(line(report, "mcp")).toMatchObject({ ok: false });
    expect(line(report, "mcp")?.detail).toContain(command[1]);
  });

  test("mcp fails when the entry is disabled or not local", async () => {
    const { adapter, command } = make();
    write(
      jsonFile(),
      JSON.stringify({ mcp: { "agent-vault": { ...entryOf(command), enabled: false } } }),
    );
    expect(line(await adapter.doctor(box.home), "mcp")).toMatchObject({ ok: false });
    write(
      jsonFile(),
      JSON.stringify({ mcp: { "agent-vault": { type: "remote", url: "https://x.test" } } }),
    );
    expect(line(await adapter.doctor(box.home), "mcp")).toMatchObject({ ok: false });
  });

  test("a config that is not JSON fails the mcp check without throwing", async () => {
    const { adapter } = make();
    write(jsonFile(), "{ nope");
    const report = await adapter.doctor(box.home);
    expect(line(report, "mcp")).toMatchObject({ ok: false });
    expect(line(report, "mcp")?.detail).toContain("not usable");
  });

  test("an opencode.jsonc entry counts", async () => {
    const { adapter } = make();
    write(jsoncFile(), COMMENTED);
    await adapter.install({ home: box.home });
    expect(line(await adapter.doctor(box.home), "mcp")).toMatchObject({ ok: true });
  });

  test("a daemon that cannot be reached fails daemon", async () => {
    const { adapter } = make({
      client: async () => {
        throw new Error("no daemon here");
      },
    });
    await adapter.install({ home: box.home });
    const report = await adapter.doctor(box.home);
    expect(line(report, "daemon")).toMatchObject({ ok: false, detail: "no daemon here" });
    expect(report.ok).toBe(false);
  });

  test("a locked or uninitialized vault fails vault", async () => {
    const { adapter } = make({
      client: async () => ({
        call: async <T>() => ({ initialized: true, locked: true }) as T,
        close() {},
      }),
    });
    expect(line(await adapter.doctor(box.home), "vault")).toMatchObject({ ok: false });
    const fresh = make({
      client: async () => ({
        call: async <T>() => ({ initialized: false, locked: true }) as T,
        close() {},
      }),
    });
    expect(line(await fresh.adapter.doctor(box.home), "vault")).toMatchObject({
      ok: false,
      fix: "agent-vault init",
    });
  });
});

describe("the rest of the interface", () => {
  test("handleHook allows every event and never contacts the daemon", async () => {
    let connects = 0;
    const { adapter } = make({
      client: async () => {
        connects++;
        throw new Error("must not be called");
      },
    });
    for (const event of ["prompt-submit", "scrub", "anything"]) {
      expect(await adapter.handleHook(event, { prompt: "x" })).toBeNull();
      expect(await adapter.handleHook(event, null, { probe: true })).toBeNull();
    }
    expect(connects).toBe(0);
  });

  test("blockOutput is null: OpenCode has no prompt hook to block", () => {
    const { adapter } = make();
    expect(adapter.blockOutput("any reason")).toBeNull();
  });

  test("historyFiles is empty: the store is SQLite", () => {
    const { adapter } = make();
    expect(adapter.historyFiles(box.home)).toEqual([]);
    expect(adapter.historyFiles(box.home, { transcript_path: "/x" })).toEqual([]);
  });

  test("detect looks for the config dir", async () => {
    const { adapter } = make();
    expect(await adapter.detect(box.home)).toBe(false);
    fs.mkdirSync(defaultDir(), { recursive: true });
    expect(await adapter.detect(box.home)).toBe(true);
  });
});
