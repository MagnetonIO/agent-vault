import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const binary = path.join(
  root,
  "dist-sea",
  `${process.platform}-${process.arch}`,
  process.platform === "win32" ? "agent-vault.exe" : "agent-vault",
);

// Needs a 120 MB binary, so it runs only in the release workflow (and by hand), after pnpm build.
describe.skipIf(!process.env.AGENT_VAULT_TEST_SEA)("SEA binary", { timeout: 120_000 }, () => {
  let dir: string;
  let env: NodeJS.ProcessEnv;
  const run = (...args: string[]) =>
    spawnSync(binary, args, { env, encoding: "utf8", windowsHide: true });

  beforeAll(() => {
    // The release workflow runs `pnpm dist` first and sets this; by hand, build here so a stale
    // binary is never what gets tested.
    if (!process.env.AGENT_VAULT_SEA_PREBUILT) {
      execFileSync(process.execPath, [path.join(root, "scripts/build-sea.mjs")], {
        cwd: root,
        stdio: "inherit",
      });
    }
    if (!fs.existsSync(binary)) throw new Error(`${binary} is missing: run pnpm dist first`);
    dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "avsea-")));
    const home = path.join(dir, "vault");
    fs.mkdirSync(home);
    fs.writeFileSync(path.join(home, "config.json"), JSON.stringify({ keystore: "keyfile" }));
    // The sandbox rule (AGENTS.md): a keyfile store and a temp home, never the real keychain.
    env = {
      ...process.env,
      HOME: dir,
      USERPROFILE: dir,
      AGENT_VAULT_HOME: home,
      XDG_RUNTIME_DIR: path.join(dir, "run"),
      AGENT_VAULT_KEYFILE_PASSPHRASE: "sea smoke passphrase 4417",
    };
    // The developer's own harness dirs must not leak in (sandbox rule).
    delete env.CLAUDE_CONFIG_DIR;
    delete env.XDG_CONFIG_HOME;
    delete env.CODEX_HOME;
  });

  afterAll(() => {
    if (!env) return;
    run("daemon", "stop");
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  it("loads the keyring addon and prints its version", () => {
    const res = run("--version");
    expect(res.stderr).toBe("");
    expect(res.stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("status starts a daemon from the binary and reports an uninitialized vault", () => {
    const res = run("status");
    expect(res.status, res.stderr).toBe(0);
    expect(res.stdout).toMatch(/initialized\s+no/);
    expect(res.stdout).toMatch(/key store\s+keyfile/);
  });
});
