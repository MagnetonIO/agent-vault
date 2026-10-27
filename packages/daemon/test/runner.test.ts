import { randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { AuditEvent } from "@agent-vault/core";
import { describe, expect, test, vi } from "vitest";
import { connect, type IpcClient } from "../src/client.js";
import { RpcError } from "../src/errors.js";
import { type Registry, registry } from "../src/methods/index.js";
import { b64, MODES, useDaemon } from "./helpers.js";

// Every test here starts real processes; a Windows runner needs far longer than the 5 s default.
vi.setConfig({ testTimeout: 30_000 });

const SECRET = "s3cr3t-token-value";
const NODE = process.execPath;
const POSIX = process.platform !== "win32";
const baseEnv = Object.fromEntries(
  Object.entries(process.env).filter((e): e is [string, string] => e[1] !== undefined),
);

type RunResult = { exitCode: number; signal?: string };

type Run = {
  runId: string;
  /** Everything received so far. */
  out: { stdout: string; stderr: string };
  /** Resolves when `needle` has shown up on `stream`. */
  seen(stream: "stdout" | "stderr", needle: string): Promise<void>;
  result: Promise<RunResult>;
};

/** Start `run.start` on `client` and collect its `run.output` notifications. */
function startRun(client: IpcClient, params: Record<string, unknown>): Run {
  const runId = (params.runId as string | undefined) ?? randomUUID();
  const out = { stdout: "", stderr: "" };
  const waiting: { stream: "stdout" | "stderr"; needle: string; resolve: () => void }[] = [];
  client.onNotification((method, p) => {
    const n = p as { runId: string; stream: "stdout" | "stderr"; data: string };
    if (method !== "run.output" || n.runId !== runId) return;
    out[n.stream] += n.data;
    for (const w of waiting)
      if (w.stream === n.stream && out[n.stream].includes(w.needle)) w.resolve();
  });
  const result = client.call<RunResult>(
    "run.start",
    { cwd: process.cwd(), baseEnv, ...params, runId },
    { timeoutMs: 0 },
  );
  result.catch(() => {});
  return {
    runId,
    out,
    seen: (stream, needle) =>
      new Promise<void>((resolve) => {
        if (out[stream].includes(needle)) resolve();
        else waiting.push({ stream, needle, resolve });
      }),
    result,
  };
}

/** The `argv` for `node -e <script>`. */
const nodeE = (script: string, ...rest: string[]): string[] => [NODE, "-e", script, ...rest];

async function rpcError(p: Promise<unknown>): Promise<RpcError> {
  try {
    await p;
  } catch (err) {
    if (err instanceof RpcError) return err;
    throw err;
  }
  throw new Error("expected an RpcError");
}

function pidGone(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return false;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "ESRCH";
  }
}

async function waitGone(pid: number, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (pidGone(pid)) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return pidGone(pid);
}

describe.each(MODES)("run and helper over %s", (mode) => {
  const env = useDaemon(mode, { init: true });

  const put = (name: string, value: string, tags?: string[]) =>
    env.client.call("secret.put", { name, valueB64: b64(value), ...(tags && { tags }) });

  const audit = () => env.client.call<AuditEvent[]>("audit.query", { limit: 100 });

  describe("redaction", () => {
    test("a printed secret comes back redacted", async () => {
      await put("t", SECRET);
      const run = startRun(env.client, {
        argv: nodeE("console.log(process.env.TOKEN)"),
        env: { TOKEN: "vault://t" },
      });
      expect(await run.result).toEqual({ exitCode: 0 });
      expect(run.out.stdout).toBe("[redacted vault://t]\n");
      expect(run.out.stderr).toBe("");
    });

    test("stderr is redacted on its own stream", async () => {
      await put("t", SECRET);
      const run = startRun(env.client, {
        argv: nodeE("console.error(process.env.TOKEN); console.log('fine')"),
        env: { TOKEN: "vault://t" },
      });
      await run.result;
      expect(run.out.stderr).toBe("[redacted vault://t]\n");
      expect(run.out.stdout).toBe("fine\n");
    });

    test("base64, base64url and urlencoded forms are redacted; hex is not", async () => {
      const value = "p@ss/w0rd+with~odd?bytes>>>";
      await put("t", value);
      const forms = {
        b64: Buffer.from(value).toString("base64"),
        b64url: Buffer.from(value).toString("base64url"),
        url: encodeURIComponent(value),
        hex: Buffer.from(value).toString("hex"),
      };
      const run = startRun(env.client, {
        argv: nodeE(
          "const f = JSON.parse(process.argv[1]); for (const k of Object.keys(f)) console.log(k + ':' + f[k])",
          JSON.stringify(forms),
        ),
        env: { TOKEN: "vault://t" },
      });
      await run.result;
      expect(run.out.stdout).toBe(
        [
          "b64:[redacted vault://t]",
          "b64url:[redacted vault://t]",
          "url:[redacted vault://t]",
          `hex:${forms.hex}`,
          "",
        ].join("\n"),
      );
    });

    test("a secret split across two writes 100 ms apart is still redacted", async () => {
      await put("t", SECRET);
      const run = startRun(env.client, {
        argv: nodeE(
          "const s = process.env.TOKEN; process.stdout.write('a ' + s.slice(0, 7));" +
            "setTimeout(() => process.stdout.write(s.slice(7) + ' b\\n'), 100)",
        ),
        env: { TOKEN: "vault://t" },
      });
      await run.result;
      expect(run.out.stdout).toBe("a [redacted vault://t] b\n");
    });

    test("a multibyte character split across chunks survives", async () => {
      const run = startRun(env.client, {
        argv: nodeE(
          "const b = Buffer.from('a\\u20acb\\u{1F600}c'); process.stdout.write(b.subarray(0, 2));" +
            "setTimeout(() => process.stdout.write(b.subarray(2, 6)), 80);" +
            "setTimeout(() => process.stdout.write(b.subarray(6)), 160)",
        ),
      });
      await run.result;
      expect(run.out.stdout).toBe("a€b\u{1F600}c");
    });

    test("a secret under 4 characters is an app error and the child never runs", async () => {
      await put("tiny", "abc");
      const marker = path.join(env.dir, "ran");
      const err = await rpcError(
        startRun(env.client, {
          argv: nodeE("require('fs').writeFileSync(process.argv[1], 'x')", marker),
          env: { TOKEN: "vault://tiny" },
        }).result,
      );
      expect(err.code).toBe(-32000);
      expect(err.data).toEqual({ name: "RunError" });
      expect(err.message).toContain("tiny");
      expect(err.message).not.toContain('abc"');
      expect(fs.existsSync(marker)).toBe(false);
    });
  });

  describe("environment", () => {
    test("layers: baseEnv < bundle < envFile < explicit env", async () => {
      await put("from-bundle", "bundle-secret-1");
      await put("from-file", "file-secret-22");
      await put("from-env", "env-secret-333");
      await env.client.call("bundle.create", { name: "layers" });
      for (const [e, s] of [
        ["A", "from-bundle"],
        ["B", "from-bundle"],
        ["C", "from-bundle"],
      ] as const) {
        await env.client.call("bundle.grant", { bundle: "layers", env: e, secret: s });
      }
      fs.writeFileSync(
        path.join(env.dir, "app.env"),
        "B=vault://from-file\nC=vault://from-file\nLIT=plain value\n",
      );
      const run = startRun(env.client, {
        argv: nodeE(
          "const e = process.env; console.log([e.A, e.B, e.C, e.D, e.LIT, e.BASE].join('|'))",
        ),
        cwd: env.dir,
        baseEnv: { ...baseEnv, A: "base-a", B: "base-b", BASE: "kept" },
        bundle: "layers",
        envFile: "app.env",
        env: { C: "vault://from-env", D: "vault://from-env" },
      });
      expect(await run.result).toEqual({ exitCode: 0 });
      expect(run.out.stdout).toBe(
        "[redacted vault://from-bundle]|[redacted vault://from-file]|[redacted vault://from-env]|" +
          "[redacted vault://from-env]|plain value|kept\n",
      );
    });

    test("an absolute envFile path works", async () => {
      await put("t", SECRET);
      const file = path.join(env.dir, "abs.env");
      fs.writeFileSync(file, `export TOKEN="vault://t"\nPLAIN=ok # comment\n`);
      const run = startRun(env.client, {
        argv: nodeE("console.log(process.env.TOKEN, process.env.PLAIN)"),
        envFile: file,
      });
      await run.result;
      expect(run.out.stdout).toBe("[redacted vault://t] ok\n");
    });

    test("a literal in explicit env is -32602", async () => {
      const err = await rpcError(
        startRun(env.client, { argv: nodeE("0"), env: { TOKEN: "not-a-ref" } }).result,
      );
      expect(err.code).toBe(-32602);
      expect(err.message).not.toContain("not-a-ref");
    });

    test("a removed secret leaves a stale grant that is SecretNotFoundError", async () => {
      await put("gone", SECRET);
      await env.client.call("bundle.create", { name: "stale" });
      await env.client.call("bundle.grant", { bundle: "stale", env: "TOKEN", secret: "gone" });
      await env.client.call("secret.remove", { name: "gone" });
      const err = await rpcError(
        startRun(env.client, { argv: nodeE("console.log('ran')"), bundle: "stale" }).result,
      );
      expect(err.data).toEqual({ name: "SecretNotFoundError" });
      expect(err.message).toContain("gone");
    });

    test("a missing secret in env names the secret", async () => {
      const err = await rpcError(
        startRun(env.client, { argv: nodeE("0"), env: { TOKEN: "vault://nope" } }).result,
      );
      expect(err.data).toEqual({ name: "SecretNotFoundError" });
      expect(err.message).toContain("nope");
    });

    test("an unknown bundle is BundleNotFoundError", async () => {
      const err = await rpcError(
        startRun(env.client, { argv: nodeE("0"), bundle: "nobody" }).result,
      );
      expect(err.data).toEqual({ name: "BundleNotFoundError" });
    });
  });

  describe("params", () => {
    test.each([
      ["no argv", { argv: [] }],
      ["an empty argv[0]", { argv: [""] }],
      ["a relative cwd", { argv: nodeE("0"), cwd: "relative/dir" }],
      ["a non-string baseEnv value", { argv: nodeE("0"), baseEnv: { A: 1 } }],
      ["a bad runId", { argv: nodeE("0"), runId: "not-a-uuid" }],
      ["an unknown key", { argv: nodeE("0"), shell: true }],
    ])("%s is -32602", async (_label, params) => {
      const err = await rpcError(startRun(env.client, params).result);
      expect(err.code).toBe(-32602);
    });

    test("a run id already in use is an app error", async () => {
      const runId = randomUUID();
      const first = startRun(env.client, {
        runId,
        argv: nodeE("console.log('up'); process.stdin.resume()"),
      });
      await first.seen("stdout", "up");
      const err = await rpcError(startRun(env.client, { runId, argv: nodeE("0") }).result);
      expect(err.data).toEqual({ name: "RunError" });
      await env.client.call("run.stdin", { runId, end: true });
      expect(await first.result).toEqual({ exitCode: 0 });
    });

    test("a command that does not exist is an app error", async () => {
      const err = await rpcError(
        startRun(env.client, { argv: [path.join(env.dir, "no-such-command")] }).result,
      );
      expect(err.code).toBe(-32000);
      expect(err.data).toEqual({ name: "RunError" });
    });
  });

  describe("exit and streams", () => {
    test("the exit code is passed through", async () => {
      const run = startRun(env.client, { argv: nodeE("process.exit(7)") });
      expect(await run.result).toEqual({ exitCode: 7 });
    });

    test("stdin round-trips", async () => {
      const run = startRun(env.client, { argv: nodeE("process.stdin.pipe(process.stdout)") });
      // Straight after run.start: the run is registered before the daemon reads the next request.
      await env.client.call("run.stdin", { runId: run.runId, dataB64: b64("hello ") });
      await env.client.call("run.stdin", { runId: run.runId, dataB64: b64("world\n"), end: true });
      expect(await run.result).toEqual({ exitCode: 0 });
      expect(run.out.stdout).toBe("hello world\n");
    });

    test.runIf(POSIX)("run.signal SIGTERM ends the child with 143", async () => {
      const run = startRun(env.client, {
        argv: nodeE("console.log('up'); setInterval(() => {}, 1000)"),
      });
      await run.seen("stdout", "up");
      await env.client.call("run.signal", { runId: run.runId, signal: "SIGTERM" });
      expect(await run.result).toEqual({ exitCode: 143, signal: "SIGTERM" });
    });

    test("run.signal rejects a signal outside the allowed set", async () => {
      const run = startRun(env.client, {
        argv: nodeE("console.log('up'); process.stdin.resume()"),
      });
      await run.seen("stdout", "up");
      const err = await rpcError(
        env.client.call("run.signal", { runId: run.runId, signal: "SIGUSR1" }),
      );
      expect(err.code).toBe(-32602);
      await env.client.call("run.stdin", { runId: run.runId, end: true });
      await run.result;
    });

    test("run.stdin and run.signal for an unknown run are app errors", async () => {
      for (const [method, extra] of [
        ["run.stdin", { end: true }],
        ["run.signal", { signal: "SIGTERM" }],
      ] as const) {
        const err = await rpcError(env.client.call(method, { runId: randomUUID(), ...extra }));
        expect(err.data).toEqual({ name: "RunError" });
      }
    });

    test("another connection cannot write to or signal a run", async () => {
      const run = startRun(env.client, {
        argv: nodeE("console.log('up'); process.stdin.pipe(process.stdout)"),
      });
      await run.seen("stdout", "up");
      const other = await env.connect();
      for (const [method, extra] of [
        ["run.stdin", { dataB64: b64("evil"), end: true }],
        ["run.signal", { signal: "SIGKILL" }],
      ] as const) {
        const err = await rpcError(other.call(method, { runId: run.runId, ...extra }));
        expect(err.code).toBe(-32000);
        expect(err.data).toEqual({ name: "RunError" });
      }
      // The owner is unaffected and still in control.
      await env.client.call("run.stdin", { runId: run.runId, dataB64: b64("ok\n"), end: true });
      expect(await run.result).toEqual({ exitCode: 0 });
      expect(run.out.stdout).toBe("up\nok\n");
    });
  });

  describe("lifetime", () => {
    const pidOf = (run: Run) => run.seen("stdout", "\n").then(() => Number(run.out.stdout.trim()));

    test("a client that disconnects has its child terminated", async () => {
      const owner = await connect(env.endpoint);
      const run = startRun(owner, {
        argv: nodeE("console.log(process.pid); setInterval(() => {}, 1000)"),
      });
      const pid = await pidOf(run);
      expect(pidGone(pid)).toBe(false);
      owner.close();
      expect(await waitGone(pid, 6000)).toBe(true);
    });

    test.runIf(POSIX && mode === MODES[0])(
      "a child that ignores SIGTERM is SIGKILLed within 6 s",
      async () => {
        const owner = await connect(env.endpoint);
        const run = startRun(owner, {
          argv: nodeE(
            "process.on('SIGTERM', () => {}); console.log(process.pid); setInterval(() => {}, 1000)",
          ),
        });
        const pid = await pidOf(run);
        owner.close();
        await new Promise((r) => setTimeout(r, 1000));
        expect(pidGone(pid)).toBe(false); // still alive: it shrugged SIGTERM off
        expect(await waitGone(pid, 6000)).toBe(true);
      },
    );

    test("daemon.close terminates running children", async () => {
      const run = startRun(env.client, {
        argv: nodeE("console.log(process.pid); setInterval(() => {}, 1000)"),
      });
      const pid = await pidOf(run);
      await env.daemon.close();
      expect(pidGone(pid)).toBe(true);
      await run.result.catch(() => {});
    });
  });

  describe("exe allowlist", () => {
    const bundleWith = async (name: string, exes: string[]) => {
      await env.client.call("bundle.create", { name });
      for (const path of exes) await env.client.call("bundle.allowExe", { bundle: name, path });
    };

    test("an exe outside the bundle's list is ExeNotAllowedError, and is audited as blocked", async () => {
      await put("t", SECRET);
      await bundleWith("locked", [path.join(env.dir, "only-this-one")]);
      await env.client.call("bundle.grant", { bundle: "locked", env: "TOKEN", secret: "t" });
      const marker = path.join(env.dir, "ran");
      const err = await rpcError(
        startRun(env.client, {
          argv: nodeE("require('fs').writeFileSync(process.argv[1], 'x')", marker),
          bundle: "locked",
        }).result,
      );
      expect(err.code).toBe(-32000);
      expect(err.data).toEqual({ name: "ExeNotAllowedError" });
      expect(err.message).toContain(fs.realpathSync.native(NODE));
      expect(fs.existsSync(marker)).toBe(false);

      const events = (await audit()).filter((e) => e.operation === "run");
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({ outcome: "blocked", bundle: "locked" });
      expect(events[0]?.secretName).toBeUndefined();
    });

    test("the listed exe runs, found through baseEnv PATH", async () => {
      await bundleWith("ok", [NODE]);
      const pathKey = Object.keys(baseEnv).find((k) => k.toUpperCase() === "PATH") ?? "PATH";
      const run = startRun(env.client, {
        argv: ["node", "-e", "console.log('hi')"],
        bundle: "ok",
        baseEnv: { ...baseEnv, [pathKey]: path.dirname(NODE) },
      });
      expect(await run.result).toEqual({ exitCode: 0 });
      expect(run.out.stdout).toBe("hi\n");
    });

    test.runIf(POSIX)("a symlink to an allowed exe is accepted", async () => {
      const link = path.join(env.dir, "link-to-node");
      fs.symlinkSync(NODE, link);
      await bundleWith("sym", [NODE]);
      const run = startRun(env.client, {
        argv: [link, "-e", "console.log('via link')"],
        bundle: "sym",
      });
      expect(await run.result).toEqual({ exitCode: 0 });
      expect(run.out.stdout).toBe("via link\n");
    });

    test.runIf(POSIX)("a different exe with the same basename is rejected", async () => {
      const dir = path.join(env.dir, "elsewhere");
      fs.mkdirSync(dir);
      const impostor = path.join(dir, path.basename(NODE));
      fs.copyFileSync("/bin/sh", impostor);
      fs.chmodSync(impostor, 0o755);
      await bundleWith("same-name", [NODE]);
      const err = await rpcError(
        startRun(env.client, { argv: [impostor, "-c", "echo pwned"], bundle: "same-name" }).result,
      );
      expect(err.data).toEqual({ name: "ExeNotAllowedError" });
    });

    test("a PATH override from a grant cannot redirect the checked exe", async () => {
      // The check resolves against baseEnv.PATH, so the spawn must use that resolution too.
      const dir = path.join(env.dir, "decoy");
      fs.mkdirSync(dir);
      await put("p", dir);
      await bundleWith("pathy", [NODE]);
      await env.client.call("bundle.grant", { bundle: "pathy", env: "PATH", secret: "p" });
      const pathKey = Object.keys(baseEnv).find((k) => k.toUpperCase() === "PATH") ?? "PATH";
      const run = startRun(env.client, {
        argv: ["node", "-e", "console.log('real node')"],
        bundle: "pathy",
        baseEnv: { ...baseEnv, [pathKey]: path.dirname(NODE) },
      });
      expect(await run.result).toEqual({ exitCode: 0 });
      expect(run.out.stdout).toBe("real node\n");
    });

    test("an unresolvable argv[0] with an allowlist is an app error", async () => {
      await bundleWith("nf", [NODE]);
      const err = await rpcError(
        startRun(env.client, { argv: [path.join(env.dir, "missing")], bundle: "nf" }).result,
      );
      expect(err.data).toEqual({ name: "RunError" });
    });

    test("a bundle with no exes allows any command", async () => {
      await env.client.call("bundle.create", { name: "open" });
      const run = startRun(env.client, { argv: nodeE("console.log('any')"), bundle: "open" });
      expect(await run.result).toEqual({ exitCode: 0 });
    });
  });

  describe("audit", () => {
    test("one brokered event per injected secret", async () => {
      await put("a", "secret-a-value");
      await put("b", "secret-b-value");
      await env.client.call("bundle.create", { name: "two" });
      await env.client.call("bundle.grant", { bundle: "two", env: "A", secret: "a" });
      const run = startRun(env.client, {
        argv: nodeE("0"),
        bundle: "two",
        env: { B: "vault://b", B2: "vault://b" },
        harness: "codex",
      });
      await run.result;
      const events = (await audit()).filter((e) => e.operation === "run");
      expect(events.map((e) => e.secretName).sort()).toEqual(["a", "b"]);
      for (const e of events) {
        expect(e).toMatchObject({ outcome: "brokered", harness: "codex", bundle: "two" });
      }
      expect(JSON.stringify(events)).not.toContain("secret-a-value");
    });

    test("a secret overridden by a later layer is not injected or audited", async () => {
      await put("a", "secret-a-value");
      await env.client.call("bundle.create", { name: "ov" });
      await env.client.call("bundle.grant", { bundle: "ov", env: "A", secret: "a" });
      fs.writeFileSync(path.join(env.dir, "ov.env"), "A=plain\n");
      const run = startRun(env.client, {
        argv: nodeE("console.log(process.env.A)"),
        cwd: env.dir,
        bundle: "ov",
        envFile: "ov.env",
      });
      await run.result;
      expect(run.out.stdout).toBe("plain\n");
      expect((await audit()).filter((e) => e.operation === "run")).toHaveLength(0);
    });
  });

  describe("helper.get", () => {
    test("returns the value of a secret tagged helper, and audits it", async () => {
      await put("model/key", "sk-model-key-12345", ["helper"]);
      const got = await env.client.call("helper.get", {
        secret: "model/key",
        harness: "claude-code",
      });
      expect(got).toEqual({ value: "sk-model-key-12345" });
      const events = (await audit()).filter((e) => e.operation === "helper.get");
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        outcome: "brokered",
        secretName: "model/key",
        harness: "claude-code",
      });
      expect(JSON.stringify(events)).not.toContain("sk-model-key-12345");
    });

    test("refuses an untagged secret, names only the secret, and audits it as blocked", async () => {
      await put("plain", "plain-secret-value");
      const err = await rpcError(env.client.call("helper.get", { secret: "plain" }));
      expect(err.code).toBe(-32000);
      expect(err.data).toEqual({ name: "HelperNotAllowedError" });
      expect(err.message).toContain("plain");
      expect(JSON.stringify(err)).not.toContain("plain-secret-value");
      const events = (await audit()).filter((e) => e.operation === "helper.get");
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({ outcome: "blocked", secretName: "plain" });
    });

    test("an unknown secret is SecretNotFoundError", async () => {
      const err = await rpcError(env.client.call("helper.get", { secret: "missing" }));
      expect(err.data).toEqual({ name: "SecretNotFoundError" });
    });

    test("is the only method that returns secret bytes", () => {
      const leaking = Object.entries(registry)
        .filter(([, def]) => def.returnsSecret)
        .map(([name]) => name);
      expect(leaking).toEqual(["helper.get"]);
    });
  });
});

describe("IpcClient.call timeout option", () => {
  const methods: Registry = {
    ...registry,
    "test.sleep": {
      mutates: false,
      returnsSecret: false,
      handler: () => new Promise((resolve) => setTimeout(() => resolve("slept"), 300)),
    },
  };
  const env = useDaemon(MODES[0] ?? "tcp", { init: true, methods });

  test("timeoutMs overrides the connection default, and 0 means no timeout", async () => {
    const short = await connect(env.endpoint, { requestTimeoutMs: 50 });
    try {
      await expect(short.call("test.sleep")).rejects.toThrow(/timed out/);
      await expect(short.call("test.sleep", undefined, { timeoutMs: 0 })).resolves.toBe("slept");
      await expect(short.call("test.sleep", undefined, { timeoutMs: 5000 })).resolves.toBe("slept");
      await expect(short.call("test.sleep", undefined, { timeoutMs: 20 })).rejects.toThrow(
        /timed out/,
      );
    } finally {
      short.close();
    }
  });
});

describe.runIf(process.platform === "win32")("Windows .cmd shims", () => {
  const env = useDaemon("tcp", { init: true });

  test("a shim receives arguments with spaces, &, ^ and quotes exactly", async () => {
    fs.writeFileSync(
      path.join(env.dir, "echo-args.js"),
      "process.stdout.write(JSON.stringify(process.argv.slice(2)))",
    );
    const shim = path.join(env.dir, "shim.cmd");
    fs.writeFileSync(shim, `@"${NODE}" "%~dp0echo-args.js" %*\r\n`);
    const args = ["two words", "a&b", "c^d", 'say "hi"', 'all & of ^ it "together"'];
    const run = startRun(env.client, { argv: [shim, ...args], cwd: env.dir });
    expect(await run.result).toEqual({ exitCode: 0 });
    expect(JSON.parse(run.out.stdout)).toEqual(args);
  });

  test("a shim found through PATH and PATHEXT runs, with a secret redacted", async () => {
    await env.client.call("secret.put", { name: "t", valueB64: b64(SECRET) });
    fs.writeFileSync(
      path.join(env.dir, "printenv.cmd"),
      `@"${NODE}" -e "console.log(process.env.TOKEN)"\r\n`,
    );
    const pathKey = Object.keys(baseEnv).find((k) => k.toUpperCase() === "PATH") ?? "PATH";
    const run = startRun(env.client, {
      argv: ["printenv"],
      cwd: env.dir,
      baseEnv: { ...baseEnv, [pathKey]: env.dir },
      env: { TOKEN: "vault://t" },
    });
    expect(await run.result).toEqual({ exitCode: 0 });
    expect(run.out.stdout).toBe("[redacted vault://t]\n");
  });
});
