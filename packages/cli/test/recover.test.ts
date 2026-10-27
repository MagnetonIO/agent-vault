import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { acquireRecoverLock } from "@agent-vault/daemon";
import { getPaths } from "@agent-vault/platform";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { recover } from "../src/commands/recover.js";
import { stopDaemon } from "../src/daemon-control.js";
import { CliError } from "../src/errors.js";
import { CLI, makeSandbox, PASSPHRASE, type RunningCli, type Sandbox } from "./harness.js";

const TIMEOUT_MS = 60_000;
const NEW_PASSPHRASE = "a brand new passphrase 4410";
const SECRET = "recover-me-secret-value-8821";

describe("recover with a keyfile store", { timeout: TIMEOUT_MS }, () => {
  let sb: Sandbox;
  let saved: NodeJS.ProcessEnv;
  let words: string[];
  const spawnArgv = [process.execPath, CLI, "daemon", "run", "--passphrase-stdin", "--recovering"];
  const paths = () => getPaths({ AGENT_VAULT_HOME: sb.home });
  const backups = () => fs.readdirSync(sb.home).filter((f) => f.startsWith("keyfile.bak"));

  beforeEach(async () => {
    sb = makeSandbox();
    // `recover` runs in this process and spawns its daemon from this process's environment.
    saved = { ...process.env };
    for (const key of Object.keys(process.env)) delete process.env[key];
    Object.assign(process.env, sb.env);
    delete process.env.AGENT_VAULT_KEYFILE_PASSPHRASE;
    const init = await sb.cli(["init", "--keystore", "keyfile"]);
    expect(init.code, init.stderr).toBe(0);
    words = [...init.stdout.matchAll(/\b\d{1,2}\.\s+([a-z]+)/g)].map((m) => m[1] as string);
    fs.writeFileSync(sb.clipboard, SECRET);
    expect((await sb.cli(["grab", "kept/secret"])).code).toBe(0);
  });

  afterEach(async () => {
    await stopDaemon(paths(), true).catch(() => {});
    for (const key of Object.keys(process.env)) delete process.env[key];
    Object.assign(process.env, saved);
    sb.remove();
  });

  test("a forgotten passphrase is replaced by a new one, the secrets come back", async () => {
    // The old passphrase is gone: nothing in the environment says it.
    const lost = { AGENT_VAULT_KEYFILE_PASSPHRASE: "forgotten" };
    await sb.stopDaemon();
    expect((await sb.cli(["list"], { env: lost })).code).toBe(1);

    await recover(
      paths(),
      { words: async () => words, passphrase: async () => NEW_PASSPHRASE },
      { spawnArgv },
    );
    expect(backups()).toEqual([]);

    await sb.stopDaemon();
    const withNew = await sb.cli(["list"], {
      env: { AGENT_VAULT_KEYFILE_PASSPHRASE: NEW_PASSPHRASE },
    });
    expect(withNew.code, withNew.stderr).toBe(0);
    expect(withNew.stdout).toContain("kept/secret");

    await sb.stopDaemon();
    const withOld = await sb.cli(["list"], { env: { AGENT_VAULT_KEYFILE_PASSPHRASE: PASSPHRASE } });
    expect(withOld.code).toBe(1);
    expect(withOld.stderr).toContain(
      "wrong keyfile passphrase; if it is lost, run: agent-vault recover",
    );
  });

  test("wrong words put the old keyfile back and leave no daemon behind", async () => {
    await expect(
      recover(
        paths(),
        { words: async () => [...words].reverse(), passphrase: async () => NEW_PASSPHRASE },
        { spawnArgv },
      ),
    ).rejects.toThrow("recovery words are not valid for this vault");
    expect(backups()).toEqual([]);
    expect(await sb.daemonPid()).toBeNull();

    // The old passphrase still opens the old keyfile.
    const list = await sb.cli(["list"]);
    expect(list.code, list.stderr).toBe(0);
    expect(list.stdout).toContain("kept/secret");
  });

  test("the wrong number of words is refused before anything is touched", async () => {
    const before = fs.readFileSync(path.join(sb.home, "keyfile"), "utf8");
    await expect(
      recover(paths(), { words: async () => words.slice(1), passphrase: async () => "x" }),
    ).rejects.toThrow("expected 24 words, got 23");
    expect(fs.readFileSync(path.join(sb.home, "keyfile"), "utf8")).toBe(before);
    expect(await sb.daemonPid()).not.toBeNull(); // still running: nothing was stopped
  });

  const typed = (over: Partial<Parameters<typeof recover>[1]> = {}) => ({
    words: async () => words,
    passphrase: async () => NEW_PASSPHRASE,
    ...over,
  });

  /** Nothing of the failed attempt is left, and the old passphrase opens the old keyfile. */
  async function expectRolledBack(keyfileBefore: string) {
    expect(fs.readFileSync(path.join(sb.home, "keyfile"), "utf8")).toBe(keyfileBefore);
    expect(backups()).toEqual([]);
    expect(fs.existsSync(path.join(paths().runtimeDir, "recover.lock"))).toBe(false);
    expect(await sb.daemonPid()).toBeNull();
    const list = await sb.cli(["list"]);
    expect(list.code, list.stderr).toBe(0);
    expect(list.stdout).toContain("kept/secret");
  }

  test("while recover runs, no other command can start a daemon", async () => {
    await sb.stopDaemon();
    const release = acquireRecoverLock(paths().runtimeDir);
    try {
      const list = await sb.cli(["list"]);
      expect(list.code).toBe(1);
      expect(list.stderr).toContain("vault recovery in progress");
      const direct = await sb.cli(["daemon", "run"]);
      expect(direct.code).toBe(1);
      expect(direct.stderr).toContain("vault recovery in progress");
      // A second recover is refused too.
      await expect(recover(paths(), typed(), { spawnArgv })).rejects.toThrow(
        "vault recovery in progress",
      );
      expect(await sb.daemonPid()).toBeNull();
    } finally {
      release();
    }
    expect((await sb.cli(["list"])).code).toBe(0);
  });

  test("a recover.lock left by a dead process is reaped, not obeyed", async () => {
    await sb.stopDaemon();
    const dead = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], {
      encoding: "utf8",
    });
    fs.mkdirSync(paths().runtimeDir, { recursive: true });
    const lock = path.join(paths().runtimeDir, "recover.lock");
    fs.writeFileSync(
      lock,
      JSON.stringify({ pid: Number(dead.stdout), bootId: "", startedAt: new Date().toISOString() }),
    );
    const list = await sb.cli(["list"]);
    expect(list.code, list.stderr).toBe(0);
    expect(fs.existsSync(lock)).toBe(false);
  });

  test("a daemon that is not the one recover spawned makes it fail and roll back", async () => {
    const before = fs.readFileSync(path.join(sb.home, "keyfile"), "utf8");
    let rival: RunningCli | undefined;
    await expect(
      recover(paths(), typed(), {
        spawnArgv,
        // A daemon some hook started on the old passphrase, between the rename and our start.
        after: async (step) => {
          if (step !== "renamed") return;
          rival = sb.start(["daemon", "run", "--recovering"]);
          for (let i = 0; i < 200 && (await sb.daemonPid()) === null; i++) {
            await new Promise((r) => setTimeout(r, 50));
          }
          expect(await sb.daemonPid()).not.toBeNull();
        },
      }),
    ).rejects.toThrow("another vaultd answered instead of the one recover started");
    await rival?.done;
    await expectRolledBack(before);
  });

  test.each(["renamed", "started"] as const)(
    "SIGINT after the %s step rolls back and exits 130",
    async (step) => {
      const before = fs.readFileSync(path.join(sb.home, "keyfile"), "utf8");
      const err = await recover(paths(), typed(), {
        spawnArgv,
        after: (at) => {
          if (at === step) process.emit("SIGINT");
        },
      }).then(
        () => null,
        (e: unknown) => e as CliError,
      );
      expect(err).toBeInstanceOf(CliError);
      expect(err?.exitCode).toBe(130);
      await expectRolledBack(before);
    },
  );
});
