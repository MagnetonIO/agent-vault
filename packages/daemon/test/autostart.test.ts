import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { ipcEndpoint } from "@agent-vault/platform";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { ensureDaemon } from "../src/autostart.js";
import { connect } from "../src/client.js";
import { useTmp } from "./helpers.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const fixture = path.join(here, "fixtures", "daemon-fixture.ts");
const tsxLoader = pathToFileURL(createRequire(import.meta.url).resolve("tsx/esm")).href;

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

  test("spawns the daemon when none runs, and connects within 3 s", async () => {
    const endpoint = ipcEndpoint(tmp.paths);
    await expect(connect(endpoint)).rejects.toThrow();

    const started = Date.now();
    const client = await ensureDaemon(tmp.paths, {
      spawnArgv: [process.execPath, "--import", tsxLoader, fixture],
    });
    try {
      expect(Date.now() - started).toBeLessThan(3000);
      expect(await client.call("status")).toEqual({
        initialized: false,
        keystore: "keyfile",
        version: "0.0.0",
      });
    } finally {
      client.close();
    }
  });

  test("connects to a running daemon without spawning another", async () => {
    const argv = [process.execPath, "--import", tsxLoader, fixture];
    const first = await ensureDaemon(tmp.paths, { spawnArgv: argv });
    first.close();
    // A spawnArgv that would fail if it ran proves nothing was spawned.
    const second = await ensureDaemon(tmp.paths, {
      spawnArgv: [process.execPath, "-e", "process.exit(9)"],
    });
    expect(await second.call("status")).toMatchObject({ keystore: "keyfile" });
    second.close();
  });

  test("gives up after timeoutMs when the spawned process never serves", async () => {
    const started = Date.now();
    await expect(
      ensureDaemon(tmp.paths, { spawnArgv: [process.execPath, "-e", ""], timeoutMs: 400 }),
    ).rejects.toThrow(/did not start within 400 ms/);
    expect(Date.now() - started).toBeLessThan(2500);
  });

  test("reports a command that cannot be spawned", async () => {
    await expect(
      ensureDaemon(tmp.paths, { spawnArgv: [path.join(tmp.dir, "no-such-binary")] }),
    ).rejects.toThrow(/could not start vaultd/);
  });
});
