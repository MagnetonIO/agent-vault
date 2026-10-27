import fs from "node:fs";
import path from "node:path";
import { type BundleInfo, parseEnvFile, type SecretMeta } from "@agent-vault/core";
import { parse as parseJsonc } from "jsonc-parser";
import { parse as parseToml } from "smol-toml";
import { describe, expect, test } from "vitest";
import { fakes } from "../../detect/test/fixtures/fake-keys.js";
import {
  applyMigration,
  backupFile,
  type Finding,
  findPlaintextSecrets,
  parseWrapper,
  sanitizeName,
  wrapArgv,
} from "../src/index.js";
import { stamp, useBox } from "./helpers.js";

const box = useBox();

const write = (file: string, text: string): string => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
};
const read = (file: string): string => fs.readFileSync(file, "utf8");

const sources = () => ({ home: box.home, cwd: box.cwd, codexHome: box.codexHome });
const find = () => findPlaintextSecrets(sources());
const names = async (): Promise<string[]> =>
  (await box.client.call<SecretMeta[]>("secret.list")).map((s) => s.name).sort();
const bundles = () => box.client.call<BundleInfo[]>("bundle.list");

// One plaintext secret per source kind. Every value is generated at run time.
const PAT = fakes.githubPat();
const OPENAI = fakes.openai();
const ANTHROPIC = fakes.anthropic();
const SLACK = fakes.slack();
const FINE = fakes.githubFine();
const ALL_VALUES = [PAT, OPENAI, ANTHROPIC, SLACK, FINE];

const OPENCODE = `{
  // opencode settings
  "theme": "dark",
  "mcp": {
    // runs locally
    "fetcher": {
      "type": "local",
      "command": ["npx", "-y", "fetch-mcp"],
      "environment": { "FETCH_TOKEN": "${SLACK}", "MODE": "fast" }
    },
    /* hosted */
    "hosted": {
      "type": "remote",
      "url": "https://mcp.example.com",
      "headers": { "Authorization": "Bearer ${FINE}" }
    }
  }
}
`;

function fixtures(): { env: string; claude: string; codex: string; opencode: string } {
  const env = write(
    path.join(box.cwd, ".env"),
    `# app settings\nNODE_ENV=development\nGITHUB_TOKEN=${PAT}\n`,
  );
  const claude = write(
    path.join(box.home, ".claude.json"),
    JSON.stringify(
      {
        numStartups: 3,
        mcpServers: {
          github: {
            command: "npx",
            args: ["-y", "@modelcontextprotocol/server-github"],
            env: { OPENAI_API_KEY: OPENAI, GITHUB_API_URL: "https://api.github.com" },
          },
        },
      },
      null,
      2,
    ),
  );
  const codex = write(
    path.join(box.codexHome, "config.toml"),
    `# codex settings\nmodel = "o4"\n\n[mcp_servers.search]\ncommand = "npx"\nargs = ["-y", "search-mcp"]\n\n[mcp_servers.search.env]\nSEARCH_API_KEY = "${ANTHROPIC}"\nLOG_LEVEL = "info"\n`,
  );
  const opencode = write(path.join(box.cwd, "opencode.json"), OPENCODE);
  return { env, claude, codex, opencode };
}

const fileState = (file: string) => {
  const st = fs.statSync(file);
  return { ino: st.ino, mtimeMs: st.mtimeMs, text: read(file) };
};

describe("findPlaintextSecrets", () => {
  test("reports one finding in each of the five source kinds", async () => {
    fixtures();
    const findings = await find();
    expect(findings.map((f) => f.kind).sort()).toEqual([
      "claude-mcp",
      "codex-mcp",
      "dotenv",
      "opencode-mcp",
      "opencode-remote-header",
    ]);
    const byKind = Object.fromEntries(findings.map((f) => [f.kind, f]));
    expect(byKind.dotenv?.envName).toBe("GITHUB_TOKEN");
    expect(byKind.dotenv?.locator).toBe("line 3");
    expect(byKind["claude-mcp"]?.locator).toBe("mcpServers.github.env.OPENAI_API_KEY");
    expect(byKind["codex-mcp"]?.locator).toBe("mcp_servers.search.env.SEARCH_API_KEY");
    expect(byKind["opencode-mcp"]?.locator).toBe("mcp.fetcher.environment.FETCH_TOKEN");
    expect(byKind["opencode-remote-header"]?.locator).toBe("mcp.hosted.headers.Authorization");
  });

  test("a dry run writes nothing: files, backups and vault are untouched", async () => {
    const files = fixtures();
    const before = Object.values(files).map(fileState);
    await find();
    expect(Object.values(files).map(fileState)).toEqual(before);
    expect(fs.existsSync(box.paths.backupsDir)).toBe(false);
    expect(await names()).toEqual([]);
  });

  test("a key-name hit counts when no rule matches; refs, expansions and empties do not", async () => {
    write(
      path.join(box.cwd, ".env"),
      [
        "MY_PASSWORD=hunter2hunter2",
        "EMPTY_TOKEN=",
        "REF_KEY=vault://a/b",
        `X_SECRET=$\{OTHER}`,
        "Y_KEY=$OTHER",
        "NOTE=hello",
        "",
      ].join("\n"),
    );
    const findings = await find();
    expect(findings.map((f) => [f.envName, f.detection.ruleId])).toEqual([
      ["MY_PASSWORD", "key-name"],
    ]);
  });

  test("template files, missing sources and invalid JSON are skipped, the latter with a warning", async () => {
    write(path.join(box.cwd, ".env.example"), `API_KEY=${PAT}\n`);
    write(path.join(box.cwd, ".mcp.json"), "{ not json");
    const warnings: string[] = [];
    expect(await findPlaintextSecrets({ ...sources(), warn: (m) => warnings.push(m) })).toEqual([]);
    expect(warnings).toEqual([expect.stringContaining(".mcp.json")]);
  });

  test(".mcp.json: stdio env is a claude-mcp finding, http headers are claude-remote-header", async () => {
    write(
      path.join(box.cwd, ".mcp.json"),
      JSON.stringify({
        mcpServers: {
          local: { command: "node", args: ["s.js"], env: { A_TOKEN: PAT } },
          web: { type: "http", url: "https://x.example", headers: { "X-Api-Key": OPENAI } },
        },
      }),
    );
    expect((await find()).map((f) => f.kind).sort()).toEqual([
      "claude-mcp",
      "claude-remote-header",
    ]);
  });
});

describe("applyMigration", () => {
  const apply = async (findings: Finding[]) =>
    applyMigration(findings, box.client, { backupsDir: box.paths.backupsDir });

  test("moves every value into the vault and rewrites the files", async () => {
    const files = fixtures();
    const result = await apply(await find());
    expect(result.migrated).toBe(4);
    expect(result.listedForPhase2).toBe(1);
    expect(result.backups).toHaveLength(4);

    // .env: only the value token changed
    expect(read(files.env)).toBe(
      `# app settings\nNODE_ENV=development\nGITHUB_TOKEN=vault://github/pat-${stamp()}\n`,
    );

    // ~/.claude.json
    const claude = JSON.parse(read(files.claude));
    expect(claude.mcpServers.github).toEqual({
      command: "agent-vault",
      args: [
        "run",
        "--bundle",
        "mcp-github",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github",
      ],
      env: { GITHUB_API_URL: "https://api.github.com" },
    });
    expect(claude.numStartups).toBe(3);

    // codex TOML
    const codex = parseToml(read(files.codex)) as {
      model: string;
      mcp_servers: Record<string, { command: string; args: string[]; env: Record<string, string> }>;
    };
    expect(codex.model).toBe("o4");
    expect(codex.mcp_servers.search).toEqual({
      command: "agent-vault",
      args: ["run", "--bundle", "mcp-search", "--", "npx", "-y", "search-mcp"],
      env: { LOG_LEVEL: "info" },
    });

    // opencode: local rewritten as one command array, remote untouched
    const opencode = parseJsonc(read(files.opencode)) as {
      mcp: Record<string, { command?: string[]; environment?: object; headers?: object }>;
    };
    expect(opencode.mcp.fetcher).toMatchObject({
      type: "local",
      command: ["agent-vault", "run", "--bundle", "mcp-fetcher", "--", "npx", "-y", "fetch-mcp"],
      environment: { MODE: "fast" },
    });
    expect(opencode.mcp.hosted?.headers).toEqual({ Authorization: `Bearer ${FINE}` });

    // no value is left in a rewritten file, except the remote header that is only listed
    for (const file of [files.env, files.claude, files.codex]) {
      for (const v of ALL_VALUES) expect(read(file)).not.toContain(v);
    }
    expect(read(files.opencode)).not.toContain(SLACK);

    expect(await names()).toEqual([
      `github/pat-${stamp()}`,
      "mcp/fetcher/fetch-token",
      "mcp/github/openai-api-key",
      "mcp/search/search-api-key",
    ]);
    expect(
      (await bundles())
        .map((b) => [b.name, b.env, b.exes] as const)
        .sort((a, b) => a[0].localeCompare(b[0])),
    ).toEqual([
      ["mcp-fetcher", { FETCH_TOKEN: "mcp/fetcher/fetch-token" }, []],
      ["mcp-github", { OPENAI_API_KEY: "mcp/github/openai-api-key" }, []],
      ["mcp-search", { SEARCH_API_KEY: "mcp/search/search-api-key" }, []],
    ]);
  });

  test("backups hold the originals, mode 0600, named by timestamp and path", async () => {
    const files = fixtures();
    const originals = new Map(Object.values(files).map((f) => [f, read(f)]));
    const { backups } = await apply(await find());
    expect(backups.map((b) => path.dirname(b))).toEqual(Array(4).fill(box.paths.backupsDir));
    const restored = backups.map((b) => read(b)).sort();
    expect(restored).toEqual([...originals.values()].sort());
    for (const b of backups) {
      expect(path.basename(b)).toMatch(/^\d{4}-\d\d-\d\dT\d\d-\d\d-\d\d\.\d{3}Z-/);
      expect(path.basename(b)).not.toMatch(/[\\/:]/);
      if (process.platform !== "win32") expect(fs.statSync(b).mode & 0o777).toBe(0o600);
    }
  });

  test("a second run finds nothing to migrate, and changes nothing", async () => {
    const files = fixtures();
    await apply(await find());
    const after = Object.values(files).map(fileState);
    const again = await find();
    expect(again.filter((f) => f.kind !== "opencode-remote-header")).toEqual([]);
    const second = await apply(again);
    expect(second).toEqual({ migrated: 0, listedForPhase2: 1, backups: [], reformatted: [] });
    expect(Object.values(files).map(fileState)).toEqual(after);
  });

  test("opencode.json keeps its comments and layout", async () => {
    const files = fixtures();
    await apply(await find());
    const text = read(files.opencode);
    for (const c of ["// opencode settings", "// runs locally", "/* hosted */"]) {
      expect(text).toContain(c);
    }
    expect(text).toContain('  "theme": "dark",');
    expect(text).toContain('"url": "https://mcp.example.com"');
  });

  test("remote headers are listed and left exactly as they were", async () => {
    const file = write(
      path.join(box.cwd, "opencode.json"),
      `{ "mcp": { "hosted": { "type": "remote", "url": "https://x.example", "headers": { "X-Api-Key": "${OPENAI}" } } } }`,
    );
    const before = read(file);
    const result = await apply(await find());
    expect(result).toEqual({ migrated: 0, listedForPhase2: 1, backups: [], reformatted: [] });
    expect(read(file)).toBe(before);
    expect(await names()).toEqual([]);
  });

  test("dotenv: quotes, export, spacing, comments and CRLF survive; only the value changes", async () => {
    const lines = [
      "# comment line",
      `export A_API_KEY='${OPENAI}'`,
      `B_SECRET="${ANTHROPIC}" # trailing note`,
      `C_TOKEN=${PAT}   # unquoted with comment`,
      "D_PASSWORD = spaced-value-123",
      "E_PLAIN=hello",
      "",
    ];
    const file = write(path.join(box.cwd, ".env"), lines.join("\r\n"));
    const result = await apply(await find());
    expect(result.migrated).toBe(4);
    const s = stamp();
    expect(read(file)).toBe(
      [
        "# comment line",
        `export A_API_KEY='vault://openai/api-key-${s}'`,
        `B_SECRET="vault://anthropic/api-key-${s}" # trailing note`,
        `C_TOKEN=vault://github/pat-${s}   # unquoted with comment`,
        "D_PASSWORD = vault://env/proj/d-password",
        "E_PLAIN=hello",
        "",
      ].join("\r\n"),
    );
    expect(
      parseEnvFile(read(file))
        .filter((e) => e.ref)
        .map((e) => e.key),
    ).toEqual(["A_API_KEY", "B_SECRET", "C_TOKEN", "D_PASSWORD"]);
  });

  test("names that are taken get -2, -3; one value is stored once across files", async () => {
    await box.client.call("secret.put", {
      name: "mcp/github/openai-api-key",
      valueB64: Buffer.from("already-here").toString("base64"),
    });
    write(
      path.join(box.cwd, ".mcp.json"),
      JSON.stringify({ mcpServers: { github: { command: "x", env: { OPENAI_API_KEY: OPENAI } } } }),
    );
    write(
      path.join(box.cwd, ".env"),
      `OTHER_KEY=${OPENAI}\nSECOND_KEY=${PAT}\nTHIRD_KEY=${FINE}\n`,
    );
    await apply(await find());
    // the .env file is read first; OPENAI is stored once and the .mcp.json server reuses it
    expect(await names()).toEqual([
      `github/pat-${stamp()}`,
      `github/pat-${stamp()}-2`,
      "mcp/github/openai-api-key",
      `openai/api-key-${stamp()}`,
    ]);
    const bundle = (await bundles()).find((b) => b.name === "mcp-github");
    expect(bundle?.env).toEqual({ OPENAI_API_KEY: `openai/api-key-${stamp()}` });
  });

  test("a server that is already wrapped keeps its command and gains grants in its bundle", async () => {
    const file = write(
      path.join(box.home, ".claude.json"),
      JSON.stringify({
        mcpServers: {
          s: {
            command: "agent-vault",
            args: ["run", "--bundle", "mine", "--", "node", "s.js"],
            env: { NEW_TOKEN: PAT },
          },
        },
      }),
    );
    await apply(await find());
    expect(JSON.parse(read(file)).mcpServers.s).toEqual({
      command: "agent-vault",
      args: ["run", "--bundle", "mine", "--", "node", "s.js"],
    });
    expect((await bundles()).find((b) => b.name === "mine")?.env).toEqual({
      NEW_TOKEN: "mcp/s/new-token",
    });
  });

  test("a file that changed since the scan is refused and nothing is stored", async () => {
    const { env } = fixtures();
    const findings = (await find()).filter((f) => f.kind === "dotenv");
    fs.writeFileSync(env, "GITHUB_TOKEN=something-else\n");
    await expect(apply(findings)).rejects.toThrow(/changed since it was scanned/);
    expect(await names()).toEqual([]);
    expect(fs.existsSync(box.paths.backupsDir)).toBe(false);
  });

  test("a symlinked config is written through, not replaced", async () => {
    if (process.platform === "win32") return;
    const real = write(
      path.join(box.dir, "dotfiles", "claude.json"),
      JSON.stringify({ mcpServers: { a: { command: "x", env: { A_TOKEN: PAT } } } }),
    );
    const link = path.join(box.home, ".claude.json");
    fs.symlinkSync(real, link);
    await apply(await find());
    expect(fs.lstatSync(link).isSymbolicLink()).toBe(true);
    expect(JSON.parse(read(real)).mcpServers.a.command).toBe("agent-vault");
  });

  test("the file mode is kept", async () => {
    if (process.platform === "win32") return;
    const file = write(path.join(box.cwd, ".env"), `A_TOKEN=${PAT}\n`);
    fs.chmodSync(file, 0o640);
    await apply(await find());
    expect(fs.statSync(file).mode & 0o777).toBe(0o640);
  });

  test("an unusable bundle env name fails before anything is stored", async () => {
    write(
      path.join(box.home, ".claude.json"),
      JSON.stringify({ mcpServers: { a: { command: "x", env: { "BAD.TOKEN": PAT } } } }),
    );
    await expect(apply(await find())).rejects.toThrow(/environment variable name/);
    expect(await names()).toEqual([]);
    expect(fs.existsSync(box.paths.backupsDir)).toBe(false);
  });
});

describe("sanitizeName / backupFile", () => {
  test.each([
    ["env/My App/API_KEY", "env/my-app/api_key"],
    ["mcp/Some Server/x", "mcp/some-server/x"],
    ["/-weird//name-", "x/weird/x/name-"],
    ["", "x"],
  ])("sanitizeName(%j) is a legal name", (raw, want) => {
    expect(sanitizeName(raw)).toBe(want);
  });

  test("sanitizeName caps at 128 characters", () => {
    expect(sanitizeName(`a/${"b".repeat(300)}`).length).toBeLessThanOrEqual(128);
  });

  test("two backups of one file in the same millisecond do not collide", () => {
    const file = write(path.join(box.dir, "f.txt"), "x");
    const now = new Date(Date.UTC(2026, 9, 27));
    const a = backupFile(file, box.paths.backupsDir, now);
    const b = backupFile(file, box.paths.backupsDir, now);
    expect(a).not.toBe(b);
  });
});

describe("multi-line dotenv values", () => {
  const apply = (findings: Finding[]) =>
    applyMigration(findings, box.client, { backupsDir: box.paths.backupsDir });
  const warned = async () => {
    const warnings: string[] = [];
    const findings = await findPlaintextSecrets({ ...sources(), warn: (m) => warnings.push(m) });
    return { findings, warnings };
  };

  test("a quoted PEM key is a warning, not a finding, and --apply leaves the file alone", async () => {
    const file = write(path.join(box.cwd, ".env"), `PRIVATE_KEY="${fakes.pem()}"\nPLAIN=1\n`);
    const before = fileState(file);
    const { findings, warnings } = await warned();
    expect(findings).toEqual([]);
    expect(warnings).toEqual([
      `multiline value at ${file}:1; move it with: agent-vault set env/proj/private-key`,
    ]);
    expect(await apply(findings)).toEqual({
      migrated: 0,
      listedForPhase2: 0,
      backups: [],
      reformatted: [],
    });
    expect(fileState(file)).toEqual(before);
    expect(await names()).toEqual([]);
  });

  test("the body of a multi-line value is not read as entries, and later lines still are", async () => {
    const pat = fakes.githubPat();
    write(
      path.join(box.cwd, ".env"),
      `NOTE_KEY='first line\nINNER_TOKEN=${fakes.openai()}\nlast line'\nB_TOKEN=${pat}\n`,
    );
    const { findings, warnings } = await warned();
    expect(findings.map((f) => f.envName)).toEqual(["B_TOKEN"]);
    expect(findings[0]?.locator).toBe("line 4");
    expect(warnings).toHaveLength(1);
    await apply(findings);
    expect(read(path.join(box.cwd, ".env"))).toMatch(
      /^NOTE_KEY='first line\nINNER_TOKEN=.*\nlast line'\nB_TOKEN=vault:\/\//,
    );
  });

  test("an unclosed multi-line value that holds nothing secret is not even a warning", async () => {
    write(path.join(box.cwd, ".env"), 'MOTD="hello\nworld"\n');
    const { findings, warnings } = await warned();
    expect([findings, warnings]).toEqual([[], []]);
  });

  test("a quote that never closes is a typo: later lines are still scanned, the line is only warned about", async () => {
    const file = write(
      path.join(box.cwd, ".env"),
      'GREETING="oops\nDB_PASSWORD=hunter2-real-pw\nAPI_TOKEN=abcdef123456\n',
    );
    const { findings, warnings } = await warned();
    expect(findings.map((f) => f.envName)).toEqual(["DB_PASSWORD", "API_TOKEN"]);
    expect(warnings).toEqual([`unclosed quote at ${file}:1; fix the file by hand`]);
    await apply(findings);
    const lines = read(file).split("\n");
    expect(lines[0]).toBe('GREETING="oops');
    expect(lines[1]).toMatch(/^DB_PASSWORD=vault:\/\//);
    expect(lines[2]).toMatch(/^API_TOKEN=vault:\/\//);
  });

  test("the rewriter refuses a quote that never closes, so nothing is changed or stored", async () => {
    const file = write(path.join(box.cwd, ".env"), 'K_KEY="abc def\nrest"\n');
    const before = fileState(file);
    const handmade: Finding = {
      file,
      kind: "dotenv",
      locator: "line 1",
      envName: "K_KEY",
      detection: { ruleId: "key-name", value: "abc def", start: 0, end: 7, suggestedName: "" },
      jsonPath: [],
    };
    await expect(apply([handmade])).rejects.toThrow(/never closes/);
    expect(fileState(file)).toEqual(before);
    expect(await names()).toEqual([]);
    expect(fs.existsSync(box.paths.backupsDir)).toBe(false);
  });
});

describe("project-scoped and already-wrapped servers", () => {
  const apply = async (findings: Finding[]) =>
    applyMigration(findings, box.client, { backupsDir: box.paths.backupsDir });
  const PAT = fakes.githubPat();
  const OPENAI = fakes.openai();
  const DOTTED = "/Users/me/my.app/v1.2";

  const claudeJson = () =>
    write(
      path.join(box.home, ".claude.json"),
      JSON.stringify(
        {
          projects: {
            [DOTTED]: {
              mcpServers: { gh: { command: "npx", args: ["x"], env: { A_TOKEN: PAT } } },
            },
            "/other": { mcpServers: { gh: { command: "npx", env: { A_TOKEN: OPENAI } } } },
            "/same/value": { mcpServers: { gh: { command: "npx", env: { A_TOKEN: PAT } } } },
          },
        },
        null,
        2,
      ),
    );

  test("servers under projects.<path>.mcpServers are found with a structured path", async () => {
    claudeJson();
    const findings = await find();
    expect(findings.map((f) => f.jsonPath)).toEqual([
      ["projects", DOTTED, "mcpServers", "gh", "env", "A_TOKEN"],
      ["projects", "/other", "mcpServers", "gh", "env", "A_TOKEN"],
      ["projects", "/same/value", "mcpServers", "gh", "env", "A_TOKEN"],
    ]);
    expect(findings[0]?.locator).toBe(`projects.${DOTTED}.mcpServers.gh.env.A_TOKEN`);
  });

  test("they are migrated; same-named servers share a bundle unless their secrets differ", async () => {
    const file = claudeJson();
    const result = await apply(await find());
    expect(result.migrated).toBe(3);
    const projects = JSON.parse(read(file)).projects;
    expect(projects[DOTTED].mcpServers.gh).toEqual({
      command: "agent-vault",
      args: ["run", "--bundle", "mcp-gh", "--", "npx", "x"],
    });
    expect(projects["/other"].mcpServers.gh.args).toEqual([
      "run",
      "--bundle",
      "mcp-gh-2",
      "--",
      "npx",
    ]);
    expect(projects["/same/value"].mcpServers.gh.args.slice(0, 3)).toEqual([
      "run",
      "--bundle",
      "mcp-gh",
    ]);
    expect(await names()).toEqual(["mcp/gh/a-token", "mcp/gh/a-token-2"]);
    expect((await bundles()).map((b) => [b.name, b.env]).sort()).toEqual([
      ["mcp-gh", { A_TOKEN: "mcp/gh/a-token" }],
      ["mcp-gh-2", { A_TOKEN: "mcp/gh/a-token-2" }],
    ]);
    for (const v of [PAT, OPENAI]) expect(read(file)).not.toContain(v);
  });

  test("commands that already run through agent-vault are not wrapped again", async () => {
    const file = write(
      path.join(box.home, ".claude.json"),
      JSON.stringify({
        mcpServers: {
          long: {
            command: "agent-vault",
            args: ["run", "--bundle=b1", "--", "x"],
            env: { A_TOKEN: PAT },
          },
          short: {
            command: "/usr/local/bin/agent-vault",
            args: ["run", "-b", "b2", "--", "x"],
            env: { B_TOKEN: OPENAI },
          },
          bare: {
            command: "agent-vault",
            args: ["run", "--", "x"],
            env: { C_TOKEN: fakes.slack() },
          },
          own: { command: "agent-vault", args: ["mcp"], env: { D_TOKEN: fakes.anthropic() } },
        },
      }),
    );
    const warnings: string[] = [];
    const findings = await findPlaintextSecrets({ ...sources(), warn: (m) => warnings.push(m) });
    expect(findings.map((f) => f.envName)).toEqual(["A_TOKEN", "B_TOKEN", "C_TOKEN"]);
    expect(warnings).toEqual([expect.stringContaining("own runs agent-vault itself")]);
    await apply(findings);
    const s = JSON.parse(read(file)).mcpServers;
    expect(s.long).toEqual({ command: "agent-vault", args: ["run", "--bundle=b1", "--", "x"] });
    expect(s.short).toEqual({
      command: "/usr/local/bin/agent-vault",
      args: ["run", "-b", "b2", "--", "x"],
    });
    expect(s.bare).toEqual({
      command: "agent-vault",
      args: ["run", "--bundle", "mcp-bare", "--", "x"],
    });
    expect((await bundles()).map((b) => b.name).sort()).toEqual(["b1", "b2", "mcp-bare"]);
  });

  test("wrapArgv wraps once", () => {
    const once = wrapArgv(["npx", "-y", "p"], "mcp-p");
    expect(once).toEqual(["agent-vault", "run", "--bundle", "mcp-p", "--", "npx", "-y", "p"]);
    expect(wrapArgv(once, "other")).toBe(once);
  });

  test("parseWrapper knows the bare name, the single-file binary, node + main.js and the exact self words", () => {
    const self = ["/opt/node/bin/node", "/srv/av/packages/cli/dist/main.js"];
    const forms: [string[], number][] = [
      [["agent-vault"], 1],
      [["/usr/local/bin/agent-vault"], 1],
      [["C:\\Tools\\agent-vault.exe"], 1],
      [["/usr/bin/node", "/home/u/av/packages/cli/dist/main.js"], 2],
      [["C:\\node\\node.exe", "C:\\av\\node_modules\\@agent-vault\\cli\\dist\\main.js"], 2],
      [self, 2],
    ];
    for (const [prefix, words] of forms) {
      expect(parseWrapper([...prefix, "run", "-b", "b", "--", "x"], self)).toEqual({
        kind: "run",
        bundle: "b",
        words,
      });
      expect(parseWrapper([...prefix, "mcp"], self)).toEqual({ kind: "mcp", words });
      // Wrapping again leaves it, or only adds the missing bundle after the prefix.
      const named = [...prefix, "run", "--bundle", "b", "--", "x"];
      expect(wrapArgv(named, "other", self)).toBe(named);
      expect(wrapArgv([...prefix, "run", "--", "x"], "b2", self)).toEqual([
        ...prefix,
        "run",
        "--bundle",
        "b2",
        "--",
        "x",
      ]);
    }
    // Some other node script, or a binary merely called like ours, is not agent-vault.
    expect(parseWrapper(["node", "/srv/server/main.js", "run"])).toEqual({ kind: "none" });
    expect(parseWrapper(["agent-vault-helper", "run"])).toEqual({ kind: "none" });
  });

  test("with absolute command words, every config shape is wrapped with them, and re-migration does not wrap twice", async () => {
    const self = [
      process.execPath,
      path.join(box.home, "av", "packages", "cli", "dist", "main.js"),
    ];
    const claude = write(
      path.join(box.home, ".claude.json"),
      JSON.stringify({
        mcpServers: { gh: { command: "npx", args: ["-y", "gh"], env: { A_TOKEN: PAT } } },
      }),
    );
    const codex = write(
      path.join(box.codexHome, "config.toml"),
      `[mcp_servers.search]\ncommand = "npx"\nargs = ["-y", "search"]\n\n[mcp_servers.search.env]\nB_TOKEN = "${OPENAI}"\n`,
    );
    const opencode = write(
      path.join(box.home, ".config", "opencode", "opencode.json"),
      JSON.stringify({
        mcp: { f: { type: "local", command: ["npx", "-y", "f"], environment: { C_TOKEN: SLACK } } },
      }),
    );
    type TomlServer = { command: string; args: string[] };
    const codexServer = (): TomlServer =>
      (parseToml(read(codex)) as { mcp_servers: Record<string, TomlServer> }).mcp_servers
        .search as TomlServer;
    const run = (bundle: string, ...rest: string[]) => [
      ...self,
      "run",
      "--bundle",
      bundle,
      "--",
      ...rest,
    ];
    await applyMigration(await find(), box.client, {
      backupsDir: box.paths.backupsDir,
      command: self,
    });

    const gh = JSON.parse(read(claude)).mcpServers.gh;
    expect([gh.command, ...gh.args]).toEqual(run("mcp-gh", "npx", "-y", "gh"));
    const search = codexServer();
    expect([search.command, ...search.args]).toEqual(run("mcp-search", "npx", "-y", "search"));
    expect(JSON.parse(read(opencode)).mcp.f.command).toEqual(run("mcp-f", "npx", "-y", "f"));

    // A new plaintext secret on each wrapped server: migrated into the same bundle, never re-wrapped.
    const ghDef = JSON.parse(read(claude));
    ghDef.mcpServers.gh.env = { D_TOKEN: ANTHROPIC };
    write(claude, JSON.stringify(ghDef));
    const oc = JSON.parse(read(opencode));
    oc.mcp.f.environment = { E_TOKEN: FINE };
    write(opencode, JSON.stringify(oc));
    write(codex, `${read(codex)}\n[mcp_servers.search.env]\nF_TOKEN = "${fakes.awsAkid()}"\n`);
    const again = await find();
    expect(again).toHaveLength(3);
    await applyMigration(again, box.client, { backupsDir: box.paths.backupsDir, command: self });
    const gh2 = JSON.parse(read(claude)).mcpServers.gh;
    expect([gh2.command, ...gh2.args]).toEqual(run("mcp-gh", "npx", "-y", "gh"));
    const search2 = codexServer();
    expect([search2.command, ...search2.args]).toEqual(run("mcp-search", "npx", "-y", "search"));
    expect(JSON.parse(read(opencode)).mcp.f.command).toEqual(run("mcp-f", "npx", "-y", "f"));
    expect((await bundles()).map((b) => [b.name, Object.keys(b.env).sort()]).sort()).toEqual([
      ["mcp-f", ["C_TOKEN", "E_TOKEN"]],
      ["mcp-gh", ["A_TOKEN", "D_TOKEN"]],
      ["mcp-search", ["B_TOKEN", "F_TOKEN"]],
    ]);
  });

  test("claudeConfigDir and xdgConfigHome move the Claude and OpenCode user configs", async () => {
    const claude = write(
      path.join(box.dir, "moved", ".claude.json"),
      JSON.stringify({ mcpServers: { a: { command: "x", env: { A_TOKEN: PAT } } } }),
    );
    const opencode = write(
      path.join(box.dir, "xdg", "opencode", "opencode.jsonc"),
      JSON.stringify({
        mcp: { b: { type: "local", command: ["y"], environment: { B_TOKEN: OPENAI } } },
      }),
    );
    write(
      path.join(box.home, ".claude.json"),
      JSON.stringify({ mcpServers: { decoy: { command: "x", env: { C_TOKEN: SLACK } } } }),
    );
    const findings = await findPlaintextSecrets({
      ...sources(),
      claudeConfigDir: path.join(box.dir, "moved"),
      xdgConfigHome: path.join(box.dir, "xdg"),
    });
    expect(findings.map((f) => [f.file, f.envName])).toEqual([
      [claude, "A_TOKEN"],
      [opencode, "B_TOKEN"],
    ]);
  });

  test("a byte order mark is read through, and kept", async () => {
    const mcp = write(
      path.join(box.cwd, ".mcp.json"),
      `﻿${JSON.stringify({ mcpServers: { a: { command: "x", env: { A_TOKEN: PAT } } } })}`,
    );
    const oc = write(
      path.join(box.cwd, "opencode.json"),
      `﻿{ "mcp": { "b": { "type": "local", "command": ["y"], "environment": { "B_TOKEN": "${OPENAI}" } } } }`,
    );
    const findings = await find();
    expect(findings).toHaveLength(2);
    await apply(findings);
    for (const f of [mcp, oc]) {
      expect(read(f).startsWith("﻿")).toBe(true);
      expect(read(f)).toContain("agent-vault");
    }
  });

  test("a very long server name gets a capped bundle name ending in a hash", async () => {
    const server = `srv-${"x".repeat(200)}`;
    const file = write(
      path.join(box.home, ".claude.json"),
      JSON.stringify({ mcpServers: { [server]: { command: "x", env: { A_TOKEN: PAT } } } }),
    );
    await apply(await find());
    const bundle = (await bundles())[0]?.name ?? "";
    expect(bundle.length).toBeLessThanOrEqual(128);
    expect(bundle).toMatch(/^mcp-srv-x+-[0-9a-f]{8}$/);
    expect(JSON.parse(read(file)).mcpServers[server].args[2]).toBe(bundle);
    expect((await names())[0]?.length).toBeLessThanOrEqual(128);
  });

  test("every file is checked before the first is touched", async () => {
    const good = write(path.join(box.cwd, ".env"), `A_TOKEN=${PAT}\n`);
    write(
      path.join(box.home, ".claude.json"),
      JSON.stringify({ mcpServers: { a: { command: "x", env: { "BAD.TOKEN": OPENAI } } } }),
    );
    const before = fileState(good);
    await expect(apply(await find())).rejects.toThrow(/environment variable name/);
    expect(fileState(good)).toEqual(before);
    expect(await names()).toEqual([]);
    expect(fs.existsSync(box.paths.backupsDir)).toBe(false);
  });

  test("a rewritten TOML file is reported as reformatted, with its backup", async () => {
    const toml = write(
      path.join(box.codexHome, "config.toml"),
      `[mcp_servers.s]\ncommand = "x"\n[mcp_servers.s.env]\nA_TOKEN = "${PAT}"\n`,
    );
    const result = await apply(await find());
    expect(result.reformatted).toEqual([{ file: toml, backup: result.backups[0] }]);
  });
});
