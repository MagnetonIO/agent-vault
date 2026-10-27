import fs from "node:fs";
import path from "node:path";
import { getPaths } from "@agent-vault/platform";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { recover } from "../src/commands/recover.js";
import { stopDaemon } from "../src/daemon-control.js";
import { CLI, makeSandbox, PASSPHRASE, type Sandbox } from "./harness.js";

const TIMEOUT_MS = 60_000;
const NEW_PASSPHRASE = "a brand new passphrase 4410";
const SECRET = "recover-me-secret-value-8821";

describe("recover with a keyfile store", { timeout: TIMEOUT_MS }, () => {
  let sb: Sandbox;
  let saved: NodeJS.ProcessEnv;
  let words: string[];
  const spawnArgv = [process.execPath, CLI, "daemon", "run", "--passphrase-stdin"];
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
});
