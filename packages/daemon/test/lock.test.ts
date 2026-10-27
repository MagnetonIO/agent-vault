import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { MemoryKeyStore } from "@agent-vault/platform";
import { describe, expect, test } from "vitest";
import { connect } from "../src/client.js";
import { DaemonAlreadyRunningError } from "../src/errors.js";
import { startDaemon } from "../src/server.js";
import { useTmp } from "./helpers.js";

/** A pid that belonged to a process that has exited. */
function deadPid(): number {
  const r = spawnSync(process.execPath, ["-e", "process.stdout.write(String(process.pid))"], {
    encoding: "utf8",
  });
  return Number(r.stdout);
}

describe("single-instance lock", () => {
  const tmp = useTmp();
  const lockFile = () => path.join(tmp.paths.runtimeDir, "vaultd.lock");
  const start = () => startDaemon({ paths: tmp.paths, store: new MemoryKeyStore() });
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
      expect(fs.readFileSync(lockFile(), "utf8")).toBe(String(process.pid));

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
    writeLock(String(deadPid()));
    const d = await start();
    try {
      expect(fs.readFileSync(lockFile(), "utf8")).toBe(String(process.pid));
    } finally {
      await d.close();
    }
  });

  test("a lock held by a live process is respected", async () => {
    writeLock(String(process.ppid));
    await expect(start()).rejects.toBeInstanceOf(DaemonAlreadyRunningError);
    expect(fs.readFileSync(lockFile(), "utf8")).toBe(String(process.ppid));
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
