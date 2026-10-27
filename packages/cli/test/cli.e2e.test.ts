import fs from "node:fs";
import path from "node:path";
import { connect } from "@agent-vault/daemon";
import { getPaths, ipcEndpoint } from "@agent-vault/platform";
import { afterAll, beforeAll, describe, expect, test } from "vitest";
import { ALNUM, body, fakes } from "../../detect/test/fixtures/fake-keys.js";
import { alive, environOf, makeSandbox, PASSPHRASE, type Sandbox } from "./harness.js";

// Each call starts node, and the first one in a sandbox also starts the daemon (Argon2id on the
// keyfile, icacls on Windows).
const TIMEOUT_MS = 60_000;

// Built at run time: no key-shaped literal in the repo (AGENTS.md).
const PAT = fakes.githubPat();
const PAT2 = `gh${"p"}_${body(ALNUM, 36, 1201)}`;
const API_KEY = `e2e-${body(ALNUM, 30, 1202)}`;
const HELPER_VALUE = `sk-${"helper"}-${body(ALNUM, 16, 1203)}`;
const REDACTED = (name: string) => `[redacted vault://${name}]`;

/** Every sandbox made here, so the orphan check at the end covers all of them. */
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

const wordsIn = (stdout: string): string[] =>
  [...stdout.matchAll(/\b\d{1,2}\.\s+([a-z]+)/g)].map((m) => m[1] as string);

describe("agent-vault CLI", { timeout: TIMEOUT_MS }, () => {
  const sb = sandbox();
  let words: string[] = [];

  beforeAll(async () => {
    const init = await sb.cli(["init", "--keystore", "keyfile"]);
    expect(init.code, init.stderr).toBe(0);
    words = wordsIn(init.stdout);
    const pid = await sb.daemonPid();
    if (pid !== null) pidsSeen.add(pid);
  }, TIMEOUT_MS);

  test("init printed 24 recovery words and wrote the key store choice", () => {
    expect(words).toHaveLength(24);
    expect(fs.readFileSync(path.join(sb.home, "config.json"), "utf8")).toContain("keyfile");
  });

  test("init output starts with the words and tells the user to write them down", async () => {
    const other = sandbox();
    const init = await other.cli(["init", "--keystore", "keyfile"]);
    expect(init.code, init.stderr).toBe(0);
    expect(init.stdout.startsWith(" 1. ")).toBe(true);
    expect(wordsIn(init.stdout)).toHaveLength(24);
    expect(init.stdout).toContain(
      "Write these down. They are shown once and are the only way to recover this vault.",
    );
    expect(init.stdout.indexOf("Write these down")).toBeGreaterThan(init.stdout.indexOf("24."));
    // A second init is refused, and says why.
    const again = await other.cli(["init", "--keystore", "keyfile"]);
    expect(again.code).toBe(1);
    expect(wordsIn(again.stdout)).toHaveLength(0);
  });

  test("init refuses to switch key stores under a running daemon, and keeps the config", async () => {
    const res = await sb.cli(["init", "--keystore", "os"]);
    expect(res.code).toBe(1);
    expect(res.stderr).toContain("stop the running daemon first: agent-vault daemon stop");
    expect(JSON.parse(fs.readFileSync(path.join(sb.home, "config.json"), "utf8"))).toEqual({
      keystore: "keyfile",
    });
  });

  test("status reports the vault and the key store", async () => {
    const res = await sb.cli(["status"]);
    expect(res.code).toBe(0);
    expect(res.stdout).toMatch(/initialized\s+yes/);
    expect(res.stdout).toMatch(/key store\s+keyfile/);
  });

  test("grab stores the clipboard, empties it, and list shows the name but never the value", async () => {
    fs.writeFileSync(sb.clipboard, `${PAT}\n`);
    const grab = await sb.cli(["grab", "github/pat", "--tag", "ci"]);
    expect(grab.code, grab.stderr).toBe(0);
    expect(grab.stdout).toMatch(/^stored github\/pat · \S+ · 40 chars$/m);
    expect(fs.readFileSync(sb.clipboard, "utf8")).toBe("");

    const list = await sb.cli(["list"]);
    expect(list.code).toBe(0);
    expect(list.stdout).toContain("github/pat");
    expect(list.stdout).not.toContain(PAT);
    const json = await sb.cli(["list", "--json"]);
    expect(JSON.parse(json.stdout)).toMatchObject([
      { name: "github/pat", length: 40, tags: ["ci"] },
    ]);
    expect(json.stdout).not.toContain(PAT);
    expect(`${grab.stdout}${grab.stderr}${list.stderr}${json.stderr}`).not.toContain(PAT);
  });

  test("grab without a name detects the type and picks a name", async () => {
    fs.writeFileSync(sb.clipboard, PAT2);
    const grab = await sb.cli(["grab"]);
    expect(grab.code, grab.stderr).toBe(0);
    expect(grab.stdout).toMatch(/^stored \S+ · github · 40 chars$/m);
  });

  test("grab with an empty clipboard exits 1 and stores nothing", async () => {
    fs.writeFileSync(sb.clipboard, "\n");
    const before = JSON.parse((await sb.cli(["list", "--json"])).stdout) as unknown[];
    const grab = await sb.cli(["grab", "empty/one"]);
    expect(grab.code).toBe(1);
    expect(grab.stderr).toContain("clipboard is empty");
    const after = JSON.parse((await sb.cli(["list", "--json"])).stdout) as unknown[];
    expect(after).toHaveLength(before.length);
  });

  test("set without a terminal exits 2 and takes no value from stdin", async () => {
    const res = await sb.cli(["set", "piped/secret"], { stdin: `${API_KEY}\n` });
    expect(res.code).toBe(2);
    expect(res.stderr).toContain("Run this in a terminal, or use: agent-vault grab <name>");
    const list = await sb.cli(["list", "--json"]);
    expect(list.stdout).not.toContain("piped/secret");
  });

  test("run injects a secret and redacts it from the child's output", async () => {
    fs.writeFileSync(sb.clipboard, API_KEY);
    expect((await sb.cli(["grab", "svc/key"])).code).toBe(0);
    const res = await sb.cli([
      "run",
      "--env",
      "T=vault://svc/key",
      "--",
      "node",
      "-e",
      "console.log(process.env.T)",
    ]);
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout.trim()).toBe(REDACTED("svc/key"));
    expect(`${res.stdout}${res.stderr}`).not.toContain(API_KEY);
  });

  test("run exits with the child's exit code", async () => {
    const res = await sb.cli(["run", "--", "node", "-e", "process.exit(7)"]);
    expect(res.code).toBe(7);
  });

  test("run sends stderr to stderr", async () => {
    const res = await sb.cli(["run", "--", "node", "-e", "console.error('to-stderr')"]);
    expect(res.code).toBe(0);
    expect(res.stderr).toContain("to-stderr");
    expect(res.stdout).not.toContain("to-stderr");
  });

  test("run forwards stdin to the child", async () => {
    const res = await sb.cli(["run", "--", "node", "-e", "process.stdin.pipe(process.stdout)"], {
      stdin: "hello through the vault\n",
    });
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout).toBe("hello through the vault\n");
  });

  test("run does not hand the keyfile passphrase to the child", async () => {
    const res = await sb.cli([
      "run",
      "--",
      "node",
      "-e",
      "console.log(process.env.AGENT_VAULT_KEYFILE_PASSPHRASE === undefined)",
    ]);
    expect(res.stdout.trim()).toBe("true");
    expect(res.stdout).not.toContain(PASSPHRASE);
  });

  test("run reports an unknown reference and an unreadable command", async () => {
    const missing = await sb.cli(["run", "--env", "T=vault://no/such", "--", "node", "-e", "0"]);
    expect(missing.code).toBe(1);
    expect(missing.stderr).toContain("no/such");
    const bad = await sb.cli(["run", "--env", "nonsense", "--", "node"]);
    expect(bad.code).toBe(2);
  });

  test("run --env-file resolves vault:// references", async () => {
    const file = path.join(sb.dir, "app.env");
    fs.writeFileSync(file, "FROM_FILE=vault://svc/key\nPLAIN=ok\n");
    const res = await sb.cli([
      "run",
      "--env-file",
      file,
      "--",
      "node",
      "-e",
      "console.log(process.env.FROM_FILE, process.env.PLAIN)",
    ]);
    expect(res.code, res.stderr).toBe(0);
    expect(res.stdout.trim()).toBe(`${REDACTED("svc/key")} ok`);
  });

  test("helper prints a helper-tagged secret and refuses the rest", async () => {
    fs.writeFileSync(sb.clipboard, HELPER_VALUE);
    expect((await sb.cli(["grab", "anthropic", "--tag", "helper"])).code).toBe(0);
    const ok = await sb.cli(["helper", "anthropic"]);
    expect(ok.code, ok.stderr).toBe(0);
    expect(ok.stdout).toBe(`${HELPER_VALUE}\n`);

    const refused = await sb.cli(["helper", "svc/key"]);
    expect(refused.code).toBe(1);
    expect(refused.stdout).toBe("");
    expect(refused.stderr).toContain("helper");
    expect(`${refused.stdout}${refused.stderr}`).not.toContain(API_KEY);
  });

  test("bundles: create, grant, allow-exe, list, and run --bundle", async () => {
    expect((await sb.cli(["bundle", "create", "dev"])).code).toBe(0);
    expect((await sb.cli(["bundle", "grant", "dev", "API_KEY", "svc/key"])).code).toBe(0);
    expect((await sb.cli(["bundle", "allow-exe", "dev", process.execPath])).code).toBe(0);

    const list = await sb.cli(["bundle", "list"]);
    expect(list.stdout).toContain("dev");
    expect(list.stdout).toContain("API_KEY <- svc/key");
    const json = JSON.parse((await sb.cli(["bundle", "list", "--json"])).stdout) as unknown;
    expect(json).toMatchObject([{ name: "dev", env: { API_KEY: "svc/key" } }]);

    const run = await sb.cli([
      "run",
      "--bundle",
      "dev",
      "--",
      "node",
      "-e",
      "console.log(process.env.API_KEY)",
    ]);
    expect(run.code, run.stderr).toBe(0);
    expect(run.stdout.trim()).toBe(REDACTED("svc/key"));

    // An executable that is not on the list gets nothing.
    expect((await sb.cli(["bundle", "create", "narrow"])).code).toBe(0);
    expect((await sb.cli(["bundle", "grant", "narrow", "API_KEY", "svc/key"])).code).toBe(0);
    expect(
      (await sb.cli(["bundle", "allow-exe", "narrow", path.join(sb.dir, "not-node")])).code,
    ).toBe(0);
    const blocked = await sb.cli([
      "run",
      "--bundle",
      "narrow",
      "--",
      "node",
      "-e",
      "console.log(process.env.API_KEY)",
    ]);
    expect(blocked.code).toBe(1);
    expect(blocked.stderr).toContain("not allowed");
    expect(`${blocked.stdout}${blocked.stderr}`).not.toContain(API_KEY);
  });

  test("audit --verify exits 0 on an intact log; audit lists events without values", async () => {
    const verify = await sb.cli(["audit", "--verify"]);
    expect(verify.code, verify.stderr).toBe(0);
    expect(verify.stdout).toContain("audit log ok");

    const log = await sb.cli(["audit", "--secret", "svc/key", "--limit", "20"]);
    expect(log.code).toBe(0);
    expect(log.stdout).toContain("brokered");
    expect(log.stdout).not.toContain(API_KEY);
    const json = JSON.parse((await sb.cli(["audit", "--json"])).stdout) as { operation: string }[];
    expect(json.map((e) => e.operation)).toEqual(
      expect.arrayContaining(["vault.init", "secret.put", "run"]),
    );
    expect((await sb.cli(["audit", "--limit", "zero"])).code).toBe(2);
  });

  test("rm deletes a secret, and a missing one is exit 1", async () => {
    fs.writeFileSync(sb.clipboard, "to-be-removed-value-123");
    expect((await sb.cli(["grab", "tmp/gone"])).code).toBe(0);
    const rm = await sb.cli(["rm", "tmp/gone"]);
    expect(rm.code, rm.stderr).toBe(0);
    expect((await sb.cli(["list"])).stdout).not.toContain("tmp/gone");

    const missing = await sb.cli(["rm", "tmp/gone"]);
    expect(missing.code).toBe(1);
    expect(missing.stderr).toContain("no such secret");
  });

  test("recover needs a terminal", async () => {
    const res = await sb.cli(["recover"], { stdin: `${words.join(" ")}\n` });
    expect(res.code).toBe(2);
  });

  test("grab trims a single line but keeps a multi-line value exactly", async () => {
    fs.writeFileSync(sb.clipboard, "  \t single-line-token-value \r\n");
    const one = await sb.cli(["grab", "trim/one"]);
    expect(one.stdout).toMatch(/ · 23 chars$/m);

    const pem = "-----BEGIN KEY-----\nQUJDREVGR0g=\n-----END KEY-----\n";
    fs.writeFileSync(sb.clipboard, pem);
    const multi = await sb.cli(["grab", "trim/pem", "--tag", "helper"]);
    expect(multi.stdout).toContain(` · ${pem.length} chars`);
    // The final newline is part of the value (helper adds its own).
    expect((await sb.cli(["helper", "trim/pem"])).stdout).toBe(`${pem}\n`);
  });

  test("grab refuses whitespace and text that is not UTF-8", async () => {
    fs.writeFileSync(sb.clipboard, " \n\t \r\n");
    const blank = await sb.cli(["grab", "bad/blank"]);
    expect(blank.code).toBe(1);
    expect(blank.stderr).toContain("clipboard is empty");

    fs.writeFileSync(sb.clipboard, Buffer.from([0x61, 0xff, 0xfe, 0x62, 0x63, 0x64, 0x65, 0x66]));
    const binary = await sb.cli(["grab", "bad/binary"]);
    expect(binary.code).toBe(1);
    expect(binary.stderr).toContain("clipboard is not text");
    expect((await sb.cli(["list"])).stdout).not.toContain("bad/");
  });

  test("run --env: a bad argument is echoed whole, a repeated name is exit 2", async () => {
    const bad = await sb.cli(["run", "--env", "oops-no-equals", "--", "node", "-e", "0"]);
    expect(bad.code).toBe(2);
    expect(bad.stderr).toContain("got: oops-no-equals");
    const twice = await sb.cli([
      "run",
      "--env",
      "A=vault://svc/key",
      "--env",
      "A=vault://anthropic",
      "--",
      "node",
      "-e",
      "0",
    ]);
    expect(twice.code).toBe(2);
    expect(twice.stderr).toContain("A given more than once");
  });

  // Windows cannot deliver SIGINT to a process: the CLI would just be killed. The daemon side is
  // covered by runner.test.ts there.
  test.runIf(process.platform !== "win32")(
    "run relays Ctrl-C to the child and returns the child's code",
    async () => {
      const child = sb.start([
        "run",
        "--",
        "node",
        "-e",
        "process.on('SIGINT',()=>{console.log('got-int');process.exit(5)});console.log('ready');setInterval(()=>{},1000)",
      ]);
      await child.until("ready");
      child.child.kill("SIGINT");
      const res = await child.done;
      expect(res.code).toBe(5);
      expect(res.stdout).toContain("got-int");
    },
  );

  test.runIf(process.platform !== "win32")(
    "run: the 2nd Ctrl-C sends SIGTERM and the 3rd leaves with 130",
    async () => {
      const child = sb.start([
        "run",
        "--",
        "node",
        "-e",
        "process.on('SIGINT',()=>console.log('got-int'));process.on('SIGTERM',()=>console.log('got-term'));console.log('ready');setInterval(()=>{},1000)",
      ]);
      await child.until("ready");
      child.child.kill("SIGINT");
      await child.until("got-int");
      child.child.kill("SIGINT");
      await child.until("got-term");
      child.child.kill("SIGINT");
      const res = await child.done;
      expect(res.code).toBe(130);
    },
  );

  test("daemon run exits 0 when a daemon already runs", async () => {
    expect(await sb.daemonPid()).not.toBeNull();
    const res = await sb.cli(["daemon", "run"]);
    expect(res.code, res.stderr).toBe(0);
  });

  test("daemon run without a passphrase or a terminal says the keyfile store is locked", async () => {
    const quiet = sandbox();
    fs.writeFileSync(path.join(quiet.home, "config.json"), '{"keystore":"keyfile"}');
    const res = await quiet.cli(["daemon", "run"], {
      env: { AGENT_VAULT_KEYFILE_PASSPHRASE: "" },
    });
    expect(res.code).toBe(1);
    expect(res.stderr).toContain(
      "keyfile store is locked: set AGENT_VAULT_KEYFILE_PASSPHRASE or run 'agent-vault daemon run' in a terminal",
    );
    // Any other command says it too, rather than starting a daemon that cannot open the keyfile.
    const list = await quiet.cli(["list"], { env: { AGENT_VAULT_KEYFILE_PASSPHRASE: "" } });
    expect(list.code).toBe(2);
    expect(list.stderr).toContain("keyfile store is locked");
    expect(await quiet.daemonPid()).toBeNull();
  });

  test("daemon install refuses the keyfile store without a passphrase, before touching anything", async () => {
    const quiet = sandbox();
    fs.writeFileSync(path.join(quiet.home, "config.json"), '{"keystore":"keyfile"}');
    const res = await quiet.cli(["daemon", "install"], {
      env: { AGENT_VAULT_KEYFILE_PASSPHRASE: "" },
    });
    expect(res.code).toBe(1);
    expect(res.stderr).toContain(
      "the keyfile store needs a passphrase at daemon start; use --keystore os or set AGENT_VAULT_KEYFILE_PASSPHRASE in the service environment yourself",
    );
    expect(fs.readdirSync(quiet.dir).sort()).toEqual(["clipboard.txt", "vault"]);
  });

  test("daemon stop stops the daemon and a second stop says it is not running", async () => {
    const pid = await sb.daemonPid();
    expect(pid).not.toBeNull();
    const stop = await sb.cli(["daemon", "stop"]);
    expect(stop.code, stop.stderr).toBe(0);
    expect(stop.stdout).toContain("vaultd stopped");
    expect(alive(pid as number)).toBe(false);
    expect(await sb.daemonPid()).toBeNull();

    const again = await sb.cli(["daemon", "stop"]);
    expect(again.code).toBe(0);
    expect(again.stdout).toContain("not running");
    // and the vault is still there for the next command, which starts a daemon again.
    expect((await sb.cli(["list"])).stdout).toContain("github/pat");
  });
});

describe("the keyfile passphrase", { timeout: TIMEOUT_MS }, () => {
  const sb = sandbox();
  const NOT_IN_ENVIRON = [PASSPHRASE, "7731", "AGENT_VAULT_KEYFILE_PASSPHRASE"];

  /** The daemon's environment block, which any process of the same user can read. */
  async function daemonEnviron(): Promise<string | null> {
    const pid = await sb.daemonPid();
    expect(pid).not.toBeNull();
    const environ = environOf(pid as number);
    if (environ !== null) {
      // The reader works: it sees the variables the daemon was spawned with.
      expect(environ).toContain("AGENT_VAULT_HOME=");
    }
    return environ;
  }

  test("is not in vaultd's environment after init, nor after an autostarted status", async () => {
    // The CLI itself holds it in its env here; it must not reach the daemon that way.
    const init = await sb.cli(["init", "--keystore", "keyfile"]);
    expect(init.code, init.stderr).toBe(0);
    const afterInit = await daemonEnviron();
    for (const text of NOT_IN_ENVIRON) expect(afterInit ?? "").not.toContain(text);

    await sb.stopDaemon();
    expect((await sb.cli(["status"])).code).toBe(0);
    const afterStatus = await daemonEnviron();
    for (const text of NOT_IN_ENVIRON) expect(afterStatus ?? "").not.toContain(text);
  });

  test("a wrong one says to recover, and does not blame vaultd.lock", async () => {
    await sb.stopDaemon();
    const wrong = await sb.cli(["list"], {
      env: { AGENT_VAULT_KEYFILE_PASSPHRASE: "not the one" },
    });
    expect(wrong.code).toBe(1);
    expect(wrong.stderr).toContain(
      "wrong keyfile passphrase; if it is lost, run: agent-vault recover",
    );
    expect(wrong.stderr).not.toContain("vaultd.lock");

    const direct = await sb.cli(["daemon", "run"], {
      env: { AGENT_VAULT_KEYFILE_PASSPHRASE: "not the one" },
    });
    expect(direct.code).toBe(3);
    expect(direct.stderr).toContain("wrong keyfile passphrase");
    expect(await sb.daemonPid()).toBeNull();
  });
});

describe("recovery after the device key is lost", { timeout: TIMEOUT_MS }, () => {
  const sb = sandbox();

  test("a fresh passphrase and the 24 words bring the secrets back", async () => {
    const init = await sb.cli(["init", "--keystore", "keyfile"]);
    expect(init.code, init.stderr).toBe(0);
    const words = wordsIn(init.stdout);
    expect(words).toHaveLength(24);
    fs.writeFileSync(sb.clipboard, API_KEY);
    expect((await sb.cli(["grab", "kept/secret"])).code).toBe(0);
    await sb.stopDaemon();

    // The device key is gone: no keyfile. A new passphrase will define the next one.
    fs.rmSync(path.join(sb.home, "keyfile"));
    const fresh = { AGENT_VAULT_KEYFILE_PASSPHRASE: "a different passphrase 99" };
    const locked = await sb.cli(["list"], { env: fresh });
    expect(locked.code).toBe(1);
    expect(locked.stderr).toContain("vault is locked; run: agent-vault recover");
    expect((await sb.cli(["status"], { env: fresh })).stdout).toMatch(/locked\s+yes/);
    const reinit = await sb.cli(["init", "--keystore", "keyfile"], { env: fresh });
    expect(reinit.code).toBe(1);
    expect(reinit.stderr).toContain("vault is locked; run: agent-vault recover");

    const client = await connect(ipcEndpoint(getPaths({ AGENT_VAULT_HOME: sb.home })));
    try {
      expect(await client.call("vault.recover", { words })).toEqual({ ok: true });
    } finally {
      client.close();
    }
    const list = await sb.cli(["list"], { env: fresh });
    expect(list.code, list.stderr).toBe(0);
    expect(list.stdout).toContain("kept/secret");

    await sb.stopDaemon();
    const after = await sb.cli(["list"], { env: fresh });
    expect(after.stdout).toContain("kept/secret");
    // The old passphrase no longer opens the new keyfile.
    await sb.stopDaemon();
    const stale = await sb.cli(["list"]);
    expect(stale.code).toBe(1);
  });
});
