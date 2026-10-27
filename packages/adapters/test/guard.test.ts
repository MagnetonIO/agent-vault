import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { fakes } from "../../detect/test/fixtures/fake-keys.js";
import {
  CHAINED_HOOK,
  checkDiff,
  HOOK_MARKER,
  installHook,
  scanDiff,
  uninstallHook,
} from "../src/index.js";

const FP = /^github len=\d+ sha256:[0-9a-f]{8}$/;

describe("scanDiff", () => {
  const PAT = fakes.githubPat();

  test("reports file, line and fingerprint of added secrets only", () => {
    const diff = [
      "diff --git a/x.env b/x.env",
      "index 0000000..1111111 100644",
      "--- a/x.env",
      "+++ b/x.env",
      "@@ -1 +3,3 @@",
      "+NOTE=hello",
      `+TOKEN=${PAT}`,
      "+REF=vault://github/pat-20261027",
      `-OLD=${fakes.openai()}`,
    ].join("\n");
    const hits = scanDiff(diff);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: "x.env", line: 4 });
    expect(hits[0]?.fingerprint).toMatch(FP);
    expect(JSON.stringify(hits)).not.toContain(PAT);
  });

  test("an added line that looks like a file header stays an added line", () => {
    const diff = [
      "diff --git a/a.txt b/a.txt",
      "--- a/a.txt",
      "+++ b/a.txt",
      "@@ -0,0 +1,2 @@",
      "+++ b/not-a-header",
      `+${PAT}`,
      "diff --git a/dev/null b/gone.txt",
      "--- a/gone.txt",
      "+++ /dev/null",
      "@@ -1 +0,0 @@",
      `-${PAT}`,
    ].join("\n");
    expect(scanDiff(diff).map((h) => [h.file, h.line])).toEqual([["a.txt", 2]]);
  });

  test("a vault:// reference is ignored even where it looks like a key", () => {
    expect(
      scanDiff(`+++ b/f\n@@ -0,0 +1 @@\n+X=vault://${"a".repeat(40)}/${"b1".repeat(20)}`),
    ).toEqual([]);
  });
});

describe("in a git repo", () => {
  let dir: string;
  let repo: string;
  const git = (...args: string[]) =>
    execFileSync("git", args, { cwd: repo, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "avg-"));
    repo = path.join(dir, "repo");
    fs.mkdirSync(repo);
    // Never the real global git config, and never this repository's hooks.
    vi.stubEnv("HOME", dir);
    vi.stubEnv("USERPROFILE", dir);
    vi.stubEnv("GIT_CONFIG_GLOBAL", path.join(dir, "gitconfig"));
    vi.stubEnv("GIT_CONFIG_NOSYSTEM", "1");
    git("init", "-q");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  const hookPath = () => path.join(repo, ".git", "hooks", "pre-commit");

  test("check --staged sees staged additions, not unstaged or untracked ones", async () => {
    const PAT = fakes.githubPat();
    fs.writeFileSync(path.join(repo, "a.txt"), `ok\n${PAT}\n`);
    fs.writeFileSync(path.join(repo, "untracked.txt"), `${PAT}\n`);
    expect(await checkDiff({ cwd: repo, staged: true })).toEqual([]);
    git("add", "a.txt");
    const hits = await checkDiff({ cwd: repo, staged: true });
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ file: "a.txt", line: 2 });
    expect(hits[0]?.fingerprint).toMatch(FP);
    expect(await checkDiff({ cwd: repo, staged: false })).toEqual([]);
  });

  test("without --staged it checks the working tree against the index", async () => {
    fs.writeFileSync(path.join(repo, "a.txt"), "ok\n");
    git("add", "a.txt");
    fs.appendFileSync(path.join(repo, "a.txt"), `${fakes.githubPat()}\n`);
    expect(await checkDiff({ cwd: repo, staged: true })).toEqual([]);
    expect(await checkDiff({ cwd: repo, staged: false })).toHaveLength(1);
  });

  test("outside a repository it fails with the git message", async () => {
    await expect(checkDiff({ cwd: dir, staged: true })).rejects.toThrow(/git rev-parse failed/);
    await expect(installHook({ cwd: dir })).rejects.toThrow(/git rev-parse failed/);
  });

  test("install writes an executable hook that runs the check", async () => {
    const { hook, chained } = await installHook({ cwd: repo });
    expect(fs.realpathSync(hook)).toBe(fs.realpathSync(hookPath()));
    expect(chained).toBeNull();
    const text = fs.readFileSync(hook, "utf8");
    expect(text.startsWith("#!/bin/sh\n")).toBe(true);
    expect(text).toContain(HOOK_MARKER);
    expect(text).toContain('"agent-vault" guard check --staged || exit 1');
    if (process.platform !== "win32") expect(fs.statSync(hook).mode & 0o777).toBe(0o755);
    // installing again changes nothing
    await installHook({ cwd: repo });
    expect(fs.readFileSync(hook, "utf8")).toBe(text);
    expect(await uninstallHook({ cwd: repo })).toBe(true);
    expect(fs.existsSync(hook)).toBe(false);
    expect(await uninstallHook({ cwd: repo })).toBe(false);
  });

  test("an existing hook is chained, and uninstall restores it byte for byte", async () => {
    const original = Buffer.from("#!/bin/sh\r\necho original hook\r\nexit 0\r\n");
    fs.mkdirSync(path.dirname(hookPath()), { recursive: true });
    fs.writeFileSync(hookPath(), original, { mode: 0o700 });
    const { chained } = await installHook({ cwd: repo });
    expect(chained && path.basename(chained)).toBe(CHAINED_HOOK);
    expect(fs.readFileSync(hookPath(), "utf8")).toContain(HOOK_MARKER);
    expect(fs.readFileSync(path.join(path.dirname(hookPath()), CHAINED_HOOK))).toEqual(original);

    await installHook({ cwd: repo }); // idempotent: the original stays where it is
    expect(fs.readFileSync(path.join(path.dirname(hookPath()), CHAINED_HOOK))).toEqual(original);

    expect(await uninstallHook({ cwd: repo })).toBe(true);
    expect(fs.readFileSync(hookPath())).toEqual(original);
    expect(fs.existsSync(path.join(path.dirname(hookPath()), CHAINED_HOOK))).toBe(false);
    if (process.platform !== "win32") expect(fs.statSync(hookPath()).mode & 0o777).toBe(0o700);
  });

  test("uninstall leaves a hook that is not ours alone", async () => {
    fs.mkdirSync(path.dirname(hookPath()), { recursive: true });
    fs.writeFileSync(hookPath(), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    expect(await uninstallHook({ cwd: repo })).toBe(false);
    expect(fs.readFileSync(hookPath(), "utf8")).toBe("#!/bin/sh\nexit 0\n");
  });
});
