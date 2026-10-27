import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { installHook } from "@agent-vault/adapters";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { fakes } from "../../detect/test/fixtures/fake-keys.js";
import { alive, CLI, makeSandbox, type Sandbox } from "./harness.js";

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

const put = (file: string, data: string): string => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, data);
  return file;
};

describe("migrate, import", { timeout: TIMEOUT_MS }, () => {
  const sb = sandbox();
  const proj = path.join(sb.dir, "proj");
  const PAT = fakes.githubPat();
  const OPENAI = fakes.openai();
  const envFile = path.join(proj, ".env");
  const claude = path.join(sb.dir, ".claude.json");

  beforeAll(async () => {
    const init = await sb.cli(["init", "--keystore", "keyfile"]);
    expect(init.code, init.stderr).toBe(0);
    const pid = await sb.daemonPid();
    if (pid !== null) pidsSeen.add(pid);
    put(envFile, `NODE_ENV=test\nGITHUB_TOKEN=${PAT}\n`);
    put(
      claude,
      JSON.stringify({ mcpServers: { git: { command: "npx", env: { OPENAI_API_KEY: OPENAI } } } }),
    );
  }, TIMEOUT_MS);

  test("a dry run prints the counts table and fingerprints, and writes nothing", async () => {
    const before = [fs.readFileSync(envFile, "utf8"), fs.readFileSync(claude, "utf8")];
    const res = await sb.cli(["migrate"], { cwd: proj });
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout).toMatch(/dotenv\s+1/);
    expect(res.stdout).toMatch(/claude-mcp\s+1/);
    expect(res.stdout).toMatch(/total\s+2/);
    expect(res.stdout).toMatch(/github len=\d+ sha256:[0-9a-f]{8}/);
    expect(res.stdout).toContain("dry run: nothing was written");
    for (const out of [res.stdout, res.stderr]) {
      expect(out).not.toContain(PAT);
      expect(out).not.toContain(OPENAI);
    }
    expect([fs.readFileSync(envFile, "utf8"), fs.readFileSync(claude, "utf8")]).toEqual(before);

    const json = await sb.cli(["migrate", "--json"], { cwd: proj });
    expect(json.code, json.stderr).toBe(0);
    const parsed = JSON.parse(json.stdout) as { dryRun: boolean; findings: unknown[] };
    expect(parsed.dryRun).toBe(true);
    expect(parsed.findings).toHaveLength(2);
    expect(json.stdout).not.toContain(PAT);
    expect(json.stdout).not.toContain(OPENAI);
  });

  test("--apply stores the secrets, rewrites the files and says where the backups are", async () => {
    const res = await sb.cli(["migrate", "--apply"], { cwd: proj });
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout).toContain("migrated 2 · listed for phase 2: 0");
    expect(res.stdout).toContain("PLAINTEXT");
    for (const out of [res.stdout, res.stderr]) {
      expect(out).not.toContain(PAT);
      expect(out).not.toContain(OPENAI);
    }
    const backups = fs.readdirSync(path.join(sb.home, "backups"));
    expect(backups).toHaveLength(2);
    for (const b of backups) expect(res.stdout).toContain(b);

    expect(fs.readFileSync(envFile, "utf8")).toMatch(
      /^NODE_ENV=test\nGITHUB_TOKEN=vault:\/\/github\/pat-\d{8}\n$/,
    );
    const server = JSON.parse(fs.readFileSync(claude, "utf8")).mcpServers.git;
    expect(server).toEqual({
      command: "agent-vault",
      args: ["run", "--bundle", "mcp-git", "--", "npx"],
    });

    const list = await sb.cli(["list"]);
    expect(list.stdout).toMatch(/github\/pat-\d{8}\s+github/);
    expect(list.stdout).toContain("mcp/git/openai-api-key");
    const bundles = await sb.cli(["bundle", "list"]);
    expect(bundles.stdout).toContain("OPENAI_API_KEY <- mcp/git/openai-api-key");
  });

  test("a second migrate finds nothing", async () => {
    const res = await sb.cli(["migrate"], { cwd: proj });
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout).toContain("no plaintext secrets found");
  });

  test("import migrates one dotenv file, and only with --apply", async () => {
    const other = put(
      path.join(sb.dir, "elsewhere", "prod.env"),
      `STRIPE_SECRET=${fakes.slack()}\n`,
    );
    const before = fs.readFileSync(other, "utf8");
    const dry = await sb.cli(["import", other], { cwd: proj });
    expect(dry.code, dry.stderr).toBe(0);
    expect(dry.stdout).toContain("dry run");
    expect(fs.readFileSync(other, "utf8")).toBe(before);

    const applied = await sb.cli(["import", other, "--apply"], { cwd: proj });
    expect(applied.code, applied.stderr).toBe(0);
    expect(fs.readFileSync(other, "utf8")).toMatch(
      /^STRIPE_SECRET=vault:\/\/slack\/token-\d{8}\n$/,
    );

    const missing = await sb.cli(["import", path.join(sb.dir, "nope.env")], { cwd: proj });
    expect(missing.code).toBe(2);
  });
});

describe("scan", { timeout: TIMEOUT_MS }, () => {
  const sb = sandbox();
  const PAT = fakes.githubPat();

  test("exits 0 with nothing found, 1 with fingerprints only once a transcript holds a secret", async () => {
    const clean = await sb.cli(["scan"]);
    expect(clean.code, clean.stderr).toBe(0);
    expect(clean.stdout).toContain("no secrets found");

    // HOME and CODEX_HOME are both the sandbox dir
    const transcript = put(
      path.join(sb.dir, ".claude", "projects", "p", "s.jsonl"),
      `${JSON.stringify({ text: `GITHUB_TOKEN=${PAT}` })}\n`,
    );
    put(path.join(sb.dir, "sessions", "2026", "r.jsonl"), `${JSON.stringify({ text: "fine" })}\n`);
    const dirty = await sb.cli(["scan"]);
    expect(dirty.code).toBe(1);
    expect(dirty.stdout).toContain(transcript);
    expect(dirty.stdout).toMatch(/github len=\d+ sha256:[0-9a-f]{8}/);
    expect(dirty.stdout).not.toContain(PAT);
    expect(dirty.stderr).not.toContain(PAT);

    const json = await sb.cli(["scan", "--json"]);
    expect(json.code).toBe(1);
    expect(JSON.parse(json.stdout).hits).toHaveLength(1);
    expect(json.stdout).not.toContain(PAT);
    // no daemon was needed
    expect(await sb.daemonPid()).toBeNull();
  });
});

describe("guard", { timeout: TIMEOUT_MS }, () => {
  const sb = sandbox();
  const repo = path.join(sb.dir, "repo");
  const PAT = fakes.githubPat();
  const gitEnv = {
    ...sb.env,
    GIT_CONFIG_GLOBAL: path.join(sb.dir, "gitconfig"),
    GIT_CONFIG_NOSYSTEM: "1",
  };
  const git = (...args: string[]) =>
    execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.com", ...args], {
      cwd: repo,
      env: gitEnv,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });

  beforeAll(() => {
    fs.mkdirSync(repo, { recursive: true });
    git("init", "-q");
  });

  test("guard check --staged exits 1 on a secret and prints file:line and a fingerprint", async () => {
    put(path.join(repo, "a.txt"), `hello\n${PAT}\n`);
    git("add", "a.txt");
    const res = await sb.cli(["guard", "check", "--staged"], { cwd: repo, env: gitEnv });
    expect(res.code).toBe(1);
    expect(res.stdout).toMatch(/^a\.txt:2 github len=\d+ sha256:[0-9a-f]{8}$/m);
    expect(res.stdout + res.stderr).not.toContain(PAT);
    git("reset", "-q");
    const clean = await sb.cli(["guard", "check", "--staged"], { cwd: repo, env: gitEnv });
    expect(clean.code, clean.stderr).toBe(0);
  });

  test("guard check outside a repository exits 2", async () => {
    const res = await sb.cli(["guard", "check"], { cwd: sb.dir, env: gitEnv });
    expect(res.code).toBe(2);
  });

  test("the installed hook blocks a commit with a secret and lets a clean one through", async () => {
    const hooks = path.join(repo, ".git", "hooks");
    const chain = path.join(hooks, "pre-commit");
    fs.mkdirSync(hooks, { recursive: true });
    fs.writeFileSync(chain, "#!/bin/sh\necho chained-hook-ran >&2\n", { mode: 0o755 });

    // The hook starts this build of the CLI, not an `agent-vault` on PATH.
    await installHook({ cwd: repo, command: [process.execPath, CLI] });
    git("add", "a.txt");
    expect(() => git("commit", "-q", "-m", "secret")).toThrow(/possible secret/);

    put(path.join(repo, "a.txt"), "hello\n");
    git("add", "a.txt");
    const clean = spawnSync(
      "git",
      ["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", "-m", "clean"],
      { cwd: repo, env: gitEnv, encoding: "utf8" },
    );
    expect(clean.status, clean.stderr).toBe(0);
    // the hook that was there before ours still runs
    expect(clean.stderr).toContain("chained-hook-ran");
  });

  test("guard install / uninstall through the CLI chain and restore the existing hook", async () => {
    const repo2 = path.join(sb.dir, "repo2");
    fs.mkdirSync(repo2);
    execFileSync("git", ["init", "-q"], { cwd: repo2, env: gitEnv });
    const hook = path.join(repo2, ".git", "hooks", "pre-commit");
    const original = "#!/bin/sh\nexit 0\n";
    fs.mkdirSync(path.dirname(hook), { recursive: true });
    fs.writeFileSync(hook, original, { mode: 0o755 });

    const installed = await sb.cli(["guard", "install"], { cwd: repo2, env: gitEnv });
    expect(installed.code, installed.stderr).toBe(0);
    expect(fs.readFileSync(hook, "utf8")).toContain("guard check --staged");
    expect(installed.stdout).toContain("pre-commit.agent-vault-orig");

    const removed = await sb.cli(["guard", "uninstall"], { cwd: repo2, env: gitEnv });
    expect(removed.code, removed.stderr).toBe(0);
    expect(fs.readFileSync(hook, "utf8")).toBe(original);
  });
});
