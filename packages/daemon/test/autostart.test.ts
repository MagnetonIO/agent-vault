import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { ipcEndpoint } from "@agent-vault/platform";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { defaultTimeoutMs, ensureDaemon } from "../src/autostart.js";
import { connect } from "../src/client.js";
import { useTmp } from "./helpers.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(here, "fixtures", "daemon-fixture.ts");
const tsxLoader = pathToFileURL(createRequire(import.meta.url).resolve("tsx/esm")).href;

// A Windows cold start may legitimately take up to defaultTimeoutMs() (10 s); give spawn tests headroom.
const SPAWN_TEST_TIMEOUT_MS = 30_000;

describe("ensureDaemon", () => {
  const tmp = useTmp();

  // The sandbox rule: the spawned daemon sees a temp home and the headless keyfile unlock only.
  beforeEach(() => {
    vi.stubEnv("AGENT_VAULT_HOME", tmp.dir);
    vi.stubEnv("HOME", tmp.dir);
    vi.stubEnv("USERPROFILE", tmp.dir);
    vi.stubEnv("CODEX_HOME", tmp.dir);
    vi.stubEnv("AGENT_VAULT_KEYFILE_PASSPHRASE", "fixture passphrase");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  test(
    "spawns the daemon when none runs, and connects within the default timeout",
    async () => {
      const endpoint = ipcEndpoint(tmp.paths);
      await expect(connect(endpoint)).rejects.toThrow();

      const started = Date.now();
      const client = await ensureDaemon(tmp.paths, {
        spawnArgv: [process.execPath, "--import", tsxLoader, fixture],
      });
      try {
        expect(Date.now() - started).toBeLessThan(defaultTimeoutMs());
        expect(await client.call("status")).toEqual({
          initialized: false,
          keystore: "keyfile",
          version: "0.0.0",
          pid: expect.any(Number),
        });
      } finally {
        client.close();
      }
    },
    SPAWN_TEST_TIMEOUT_MS,
  );

  test(
    "connects to a running daemon without spawning another",
    async () => {
      const argv = [process.execPath, "--import", tsxLoader, fixture];
      const first = await ensureDaemon(tmp.paths, { spawnArgv: argv });
      first.close();
      // A spawnArgv that would fail if it ran proves nothing was spawned.
      const second = await ensureDaemon(tmp.paths, {
        spawnArgv: [process.execPath, "-e", "process.exit(9)"],
      });
      expect(await second.call("status")).toMatchObject({ keystore: "keyfile" });
      second.close();
    },
    SPAWN_TEST_TIMEOUT_MS,
  );

  test(
    "3 concurrent ensureDaemon calls all end up on the same daemon",
    async () => {
      const spawnArgv = [process.execPath, "--import", tsxLoader, fixture];
      const clients = await Promise.all(
        [1, 2, 3].map(() => ensureDaemon(tmp.paths, { spawnArgv })),
      );
      try {
        const pids = await Promise.all(
          clients.map(async (c) => (await c.call<{ pid: number }>("status")).pid),
        );
        expect(new Set(pids).size).toBe(1);
        expect(pids[0]).not.toBe(process.pid);
      } finally {
        for (const c of clients) c.close();
      }
    },
    SPAWN_TEST_TIMEOUT_MS,
  );

  test("gives up after timeoutMs when the spawned process never serves", async () => {
    const started = Date.now();
    await expect(
      ensureDaemon(tmp.paths, { spawnArgv: [process.execPath, "-e", ""], timeoutMs: 400 }),
    ).rejects.toThrow(/did not start within 400 ms/);
    expect(Date.now() - started).toBeLessThan(2500);
  });

  test("a child that exits non-zero fails fast and names the lock file", async () => {
    const started = Date.now();
    const err = await ensureDaemon(tmp.paths, {
      spawnArgv: [process.execPath, "-e", "process.exit(7)"],
      timeoutMs: 10_000,
    }).then(
      () => null,
      (e: unknown) => e as Error,
    );
    expect(err?.message).toMatch(/exited with code 7/);
    expect(err?.message).toContain(path.join(tmp.paths.runtimeDir, "vaultd.lock"));
    expect(Date.now() - started).toBeLessThan(2000);
  });

  test("a child that exits 0 (lost the race) keeps being waited on", async () => {
    await expect(
      ensureDaemon(tmp.paths, {
        spawnArgv: [process.execPath, "-e", "process.exit(0)"],
        timeoutMs: 500,
      }),
    ).rejects.toThrow(/did not start within 500 ms/);
  });

  test("at the deadline the error points at an existing vaultd.lock", async () => {
    fs.mkdirSync(tmp.paths.runtimeDir, { recursive: true, mode: 0o700 });
    const lock = path.join(tmp.paths.runtimeDir, "vaultd.lock");
    fs.writeFileSync(lock, JSON.stringify({ pid: process.ppid, bootId: "", startedAt: "x" }));
    await expect(
      ensureDaemon(tmp.paths, {
        spawnArgv: [process.execPath, "-e", "process.exit(0)"],
        timeoutMs: 400,
      }),
    ).rejects.toThrow(`vaultd.lock exists at ${lock}; if no daemon is running, delete it`);
  });

  test("reports a command that cannot be spawned", async () => {
    await expect(
      ensureDaemon(tmp.paths, { spawnArgv: [path.join(tmp.dir, "no-such-binary")] }),
    ).rejects.toThrow(/could not start vaultd/);
  });
});
