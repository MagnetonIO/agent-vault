import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { MemoryKeyStore } from "@agent-vault/platform";
import { describe, expect, test } from "vitest";
import { connect } from "../src/client.js";
import { DaemonAlreadyRunningError, RecoveryInProgressError } from "../src/errors.js";
import {
  acquireLock,
  acquireRecoverLock,
  readBootId,
  recoverLockPath,
  recoveryInProgress,
  sameBoot,
} from "../src/lock.js";
import { startDaemon } from "../src/server.js";
import { useTmp } from "./helpers.js";

/** A pid that belonged to a process that has exited. */
function deadPid(): number {
  const r = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], {
    encoding: "utf8",
  });
  return Number(r.stdout);
}

type LockContent = { pid: number; bootId: string; uptimeMs: number; startedAt: string };

describe("boot id", () => {
  test("the reader works on this OS and is stable within a boot", () => {
    const id = readBootId();
    if (process.platform === "win32") {
      expect(id).toBe(""); // Windows compares uptime instead
    } else {
      expect(id).toMatch(/^[0-9a-f-]{16,}$/i);
    }
    expect(sameBoot(id, readBootId())).toBe(true);
  });

  test("sameBoot: equal ids match, different ones do not, unknown never differs", () => {
    expect(sameBoot("a", "a")).toBe(true);
    expect(sameBoot("a", "b")).toBe(false);
    expect(sameBoot("", "b")).toBe(true);
    expect(sameBoot("a", "")).toBe(true);
  });
});

describe("single-instance lock", () => {
  const tmp = useTmp();
  const lockFile = () => path.join(tmp.paths.runtimeDir, "vaultd.lock");
  const start = () => startDaemon({ paths: tmp.paths, store: new MemoryKeyStore() });
  const readLock = () => JSON.parse(fs.readFileSync(lockFile(), "utf8")) as LockContent;
  /** A lock as an earlier boot would have left it: Windows has no boot id, so it records a longer uptime. */
  const writeInfo = (pid: number, bootId: string, uptimeMs?: number) =>
    writeLock(JSON.stringify({ pid, bootId, uptimeMs, startedAt: new Date().toISOString() }));
  const writeLock = (text: string) => {
    fs.mkdirSync(tmp.paths.runtimeDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(lockFile(), text);
  };

  test("5 concurrent startDaemon calls: exactly 1 wins, 4 are DaemonAlreadyRunningError", async () => {
    const results = await Promise.allSettled([1, 2, 3, 4, 5].map(start));
    const won = results.filter((r) => r.status === "fulfilled");
    const lost = results.filter((r) => r.status === "rejected");
    try {
      expect(won).toHaveLength(1);
      expect(lost).toHaveLength(4);
      for (const r of lost) expect(r.reason).toBeInstanceOf(DaemonAlreadyRunningError);

      const winner = won[0] as PromiseFulfilledResult<Awaited<ReturnType<typeof start>>>;
      const { endpoint } = winner.value;
      const files =
        endpoint.kind === "unix"
          ? fs.readdirSync(path.dirname(endpoint.path)).filter((f) => f.endsWith(".sock"))
          : fs
              .readdirSync(path.dirname(endpoint.endpointFile))
              .filter((f) => f === "endpoint.json");
      expect(files).toHaveLength(1);
      expect(readLock().pid).toBe(process.pid);

      const c = await connect(endpoint);
      expect(await c.call("status")).toMatchObject({ initialized: false });
      c.close();
    } finally {
      for (const r of won) await r.value.close();
    }
    // The losers did not take the winner's lock with them, and close() released it.
    expect(fs.existsSync(lockFile())).toBe(false);
  });

  test("close() releases the lock, so the next start succeeds", async () => {
    const first = await start();
    expect(fs.existsSync(lockFile())).toBe(true);
    await first.close();
    expect(fs.existsSync(lockFile())).toBe(false);
    await (await start()).close();
  });

  test("a stale lock holding a dead pid is recovered", async () => {
    writeInfo(deadPid(), readBootId());
    const d = await start();
    try {
      expect(readLock()).toMatchObject({ pid: process.pid, bootId: readBootId() });
    } finally {
      await d.close();
    }
  });

  test("a live pid from this boot is never reaped, and the error names the lock file", async () => {
    writeInfo(process.ppid, readBootId());
    const before = fs.readFileSync(lockFile(), "utf8");
    const err = await start().then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(DaemonAlreadyRunningError);
    expect((err as Error).message).toContain("vaultd.lock");
    expect(fs.readFileSync(lockFile(), "utf8")).toBe(before);
  });

  test("a live pid with a different boot id (pid reused after a reboot) is reaped", async () => {
    // Windows has no boot id, so "an earlier boot" there is a lock that recorded a longer uptime.
    writeInfo(process.ppid, "00000000-dead-beef-0000-000000000000", os.uptime() * 1000 + 3_600_000);
    const d = await start();
    try {
      expect(readLock()).toMatchObject({ pid: process.pid, bootId: readBootId() });
    } finally {
      await d.close();
    }
  });

  describe("Windows: uptime, not the wall clock", () => {
    const withUptime = (uptimeMs: number) =>
      writeLock(
        JSON.stringify({
          pid: process.ppid,
          bootId: "",
          uptimeMs,
          startedAt: new Date().toISOString(),
        }),
      );

    test("a live pid whose lock recorded a longer uptime is from before a reboot: reaped", () => {
      withUptime(os.uptime() * 1000 + 3_600_000);
      const release = acquireLock(tmp.paths.runtimeDir, "win32");
      expect(readLock()).toMatchObject({ pid: process.pid });
      release();
    });

    test("a live pid whose lock recorded a shorter uptime is the same boot: not reaped", () => {
      withUptime(1000);
      expect(() => acquireLock(tmp.paths.runtimeDir, "win32")).toThrow(DaemonAlreadyRunningError);
      expect(readLock().pid).toBe(process.ppid);
    });

    test("the lock we write records the uptime", async () => {
      const d = await start();
      try {
        expect(readLock().uptimeMs).toBeGreaterThan(0);
      } finally {
        await d.close();
      }
    });
  });

  test("a legacy bare-pid lock keeps the old rules", async () => {
    writeLock(String(process.ppid));
    await expect(start()).rejects.toBeInstanceOf(DaemonAlreadyRunningError);
    writeLock(String(deadPid()));
    await (await start()).close();
  });

  test("an empty lock is respected while young and recovered once older than 5 s", async () => {
    writeLock("");
    await expect(start()).rejects.toBeInstanceOf(DaemonAlreadyRunningError);
    const old = new Date(Date.now() - 6000);
    fs.utimesSync(lockFile(), old, old);
    await (await start()).close();

    writeLock("not a pid");
    fs.utimesSync(lockFile(), old, old);
    await (await start()).close();
  });

  test("a failed start releases the lock", async () => {
    // Pre-create a db file that is not a vault, so openVault fails after the lock is taken.
    fs.mkdirSync(tmp.paths.dataDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(tmp.paths.dbFile, "not a database");
    await expect(start()).rejects.toThrow();
    expect(fs.existsSync(lockFile())).toBe(false);
  });
});

describe("recover.lock", () => {
  const tmp = useTmp();

  test("one holder at a time; releasing frees it", () => {
    const dir = tmp.paths.runtimeDir;
    expect(recoveryInProgress(dir)).toBe(false);
    const release = acquireRecoverLock(dir);
    expect(recoveryInProgress(dir)).toBe(true);
    expect(() => acquireRecoverLock(dir)).toThrow(RecoveryInProgressError);
    release();
    expect(recoveryInProgress(dir)).toBe(false);
    acquireRecoverLock(dir)();
  });

  test("a lock whose owner is dead is reaped", () => {
    const dir = tmp.paths.runtimeDir;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const stale: LockContent = {
      pid: deadPid(),
      bootId: readBootId(),
      uptimeMs: os.uptime() * 1000,
      startedAt: new Date().toISOString(),
    };
    fs.writeFileSync(recoverLockPath(dir), JSON.stringify(stale));
    expect(recoveryInProgress(dir)).toBe(false);
    expect(fs.existsSync(recoverLockPath(dir))).toBe(false);

    fs.writeFileSync(recoverLockPath(dir), JSON.stringify(stale));
    acquireRecoverLock(dir)();
  });

  test("is independent of vaultd.lock", () => {
    const dir = tmp.paths.runtimeDir;
    const daemonLock = acquireLock(dir);
    const recoverLock = acquireRecoverLock(dir);
    recoverLock();
    daemonLock();
  });
});
