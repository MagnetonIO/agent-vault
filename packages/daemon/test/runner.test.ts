import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { type AuditEvent, allowExe, createBundle, initVault } from "@agent-vault/core";
import { getPaths, MemoryKeyStore } from "@agent-vault/platform";
import { afterEach, describe, expect, test, vi } from "vitest";
import { connect, type IpcClient } from "../src/client.js";
import { Connection } from "../src/connection.js";
import { RpcError } from "../src/errors.js";
import { type Registry, registry } from "../src/methods/index.js";
import { createRunnerService, prepareRun } from "../src/runner.js";
import { b64, MODES, RawPeer, type Reply, useDaemon } from "./helpers.js";

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

/** Pids of processes the tests started, killed after each test even if an assertion failed. */
const started = new Set<number>();
const track = (...pids: number[]): number[] => {
  for (const pid of pids) started.add(pid);
  return pids;
};
afterEach(() => {
  for (const pid of started) {
    for (const target of WIN_OR_GROUP(pid)) {
      try {
        process.kill(target, "SIGKILL");
      } catch {
        // already gone
      }
    }
  }
  started.clear();
});
/** A leader's pid and, on POSIX, its whole group (`-pid`). */
const WIN_OR_GROUP = (pid: number): number[] => (POSIX ? [-pid, pid] : [pid]);

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

    test("base64 wrapped at 64 and 76 columns (openssl, GNU base64) is redacted", async () => {
      const key = `sk-proj-${"Ab3dE6gH9jK2mN5pQ8sT1vW4yZ7".repeat(4)}`;
      await put("t", key);
      const run = startRun(env.client, {
        argv: nodeE(
          `const b = Buffer.from(process.env.TOKEN).toString("base64");
for (const [n, sep] of [[64, "\\n"], [76, "\\n"], [76, "\\r\\n"]]) console.log(b.match(new RegExp(".{1," + n + "}", "g")).join(sep));`,
        ),
        env: { TOKEN: "vault://t" },
      });
      await run.result;
      expect(run.out.stdout).not.toMatch(/[A-Za-z0-9+/]{20}/);
      expect(run.out.stdout).toBe("[redacted vault://t]\n".repeat(3));
    });

    test("the whole environment dumped as JSON is redacted", async () => {
      const value = 'pa"ss\\word with "quotes" 12345';
      await put("t", value);
      const run = startRun(env.client, {
        argv: nodeE("console.log(JSON.stringify(process.env))"),
        env: { TOKEN: "vault://t" },
      });
      await run.result;
      expect(run.out.stdout).toContain('"TOKEN":"[redacted vault://t]"');
      expect(run.out.stdout).not.toContain(JSON.stringify(value).slice(1, -1));
    });

    test("a prompt is delivered at once, not held back waiting for more output", async () => {
      await put("t", SECRET);
      const run = startRun(env.client, {
        argv: nodeE("process.stdout.write('Password: '); process.stdin.resume()"),
        env: { TOKEN: "vault://t" },
      });
      await run.seen("stdout", "Password: "); // would hang (and time out) if it were held
      await env.client.call("run.stdin", { runId: run.runId, end: true });
      await run.result;
    });

    test("a secret printed back to back for 20 MiB does not stall the daemon", async () => {
      await put("t", SECRET);
      const writes = 320;
      const run = startRun(env.client, {
        argv: nodeE(
          `const chunk = process.env.TOKEN.repeat(3640); // 65520 bytes
let i = 0;
(function go() {
  while (i < ${writes}) {
    i++;
    if (!process.stdout.write(chunk)) return void process.stdout.once("drain", go);
  }
})();`,
        ),
        env: { TOKEN: "vault://t" },
      });
      let notifications = 0;
      env.client.onNotification((method, p) => {
        if (method === "run.output" && (p as { runId: string }).runId === run.runId)
          notifications++;
      });
      let worstLag = 0;
      let last = performance.now();
      const probe = setInterval(() => {
        const now = performance.now();
        worstLag = Math.max(worstLag, now - last - 20);
        last = now;
      }, 20);
      try {
        expect(await run.result).toEqual({ exitCode: 0 });
      } finally {
        clearInterval(probe);
      }
      expect(run.out.stdout).toMatch(/^(\[redacted vault:\/\/t\])+$/);
      expect(notifications).toBeGreaterThan(100); // steady output, not one block at the end
      expect(worstLag).toBeLessThan(500);
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
    const pidOf = (run: Run) =>
      run.seen("stdout", "\n").then(() => track(Number(run.out.stdout.trim()))[0] as number);

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

  describe("process trees", () => {
    /** A child that starts a grandchild (once it is up) and prints "<child pid> <grandchild pid>". */
    const withGrandchild = (ignoreSigterm: boolean): string[] =>
      nodeE(
        `const { spawn } = require("child_process");
const g = spawn(process.execPath, ["-e", process.argv[1] + "console.log('ready'); setInterval(() => {}, 1000)"], { stdio: ["ignore", "pipe", "ignore"] });
g.stdout.once("data", () => { console.log(process.pid + " " + g.pid); });
setInterval(() => {}, 1000);`,
        ignoreSigterm ? "process.on('SIGTERM', () => {});" : "",
      );
    const pidsOf = (run: Run) =>
      run.seen("stdout", "\n").then(() => track(...run.out.stdout.trim().split(" ").map(Number)));

    test.runIf(POSIX)("disconnecting kills the whole process group", async () => {
      const owner = await connect(env.endpoint);
      const run = startRun(owner, { argv: withGrandchild(false) });
      const [child, grandchild] = await pidsOf(run);
      expect(pidGone(grandchild as number)).toBe(false);
      owner.close();
      expect(await waitGone(child as number, 6000)).toBe(true);
      expect(await waitGone(grandchild as number, 6000)).toBe(true);
    });

    test.runIf(POSIX)("run.signal reaches the grandchild too", async () => {
      const run = startRun(env.client, { argv: withGrandchild(false) });
      const [child, grandchild] = await pidsOf(run);
      await env.client.call("run.signal", { runId: run.runId, signal: "SIGTERM" });
      await run.result;
      expect(await waitGone(child as number, 6000)).toBe(true);
      expect(await waitGone(grandchild as number, 6000)).toBe(true);
    });

    test.runIf(POSIX && mode === MODES[0])(
      "a grandchild that ignores SIGTERM is SIGKILLed even after its parent is gone",
      async () => {
        const owner = await connect(env.endpoint);
        const run = startRun(owner, { argv: withGrandchild(true) });
        const [child, grandchild] = await pidsOf(run);
        owner.close();
        expect(await waitGone(child as number, 3000)).toBe(true);
        expect(pidGone(grandchild as number)).toBe(false);
        expect(await waitGone(grandchild as number, 6000)).toBe(true);
      },
    );

    test.runIf(POSIX)("daemon.close kills the whole process group", async () => {
      const run = startRun(env.client, { argv: withGrandchild(false) });
      const [child, grandchild] = await pidsOf(run);
      await env.daemon.close();
      expect(pidGone(child as number)).toBe(true);
      expect(await waitGone(grandchild as number, 1000)).toBe(true);
      await run.result.catch(() => {});
    });
  });

  describe("backpressure", () => {
    const MiB = 1024 * 1024;
    const CHUNKS = 800;
    const LINES_PER_CHUNK = 64;
    // About 50 MB: lines of 1000 filler chars, the token and a newline, written as fast as the pipe allows.
    const FLOOD = `const t = process.env.TOKEN;
const chunk = ("a".repeat(1000) + t + "\\n").repeat(${LINES_PER_CHUNK});
let i = 0;
(function go() {
  while (i < ${CHUNKS}) {
    i++;
    if (!process.stdout.write(chunk)) return void process.stdout.once("drain", go);
  }
})();`;

    test.runIf(mode === MODES[0])(
      "a client that stops reading does not make the daemon buffer the output",
      async () => {
        await put("t", SECRET);
        const peer = await RawPeer.open(env.endpoint);
        peer.socket.pause(); // reads nothing until we say so
        const baseline = process.memoryUsage().rss;
        peer.send(
          `${JSON.stringify({
            jsonrpc: "2.0",
            id: 1,
            method: "run.start",
            params: {
              runId: randomUUID(),
              cwd: process.cwd(),
              baseEnv,
              argv: nodeE(FLOOD),
              env: { TOKEN: "vault://t" },
            },
          })}\n`,
        );
        let peak = baseline;
        for (let i = 0; i < 30; i++) {
          await new Promise((r) => setTimeout(r, 100));
          peak = Math.max(peak, process.memoryUsage().rss);
        }
        expect(peak - baseline).toBeLessThan(20 * MiB);

        // Now read it all, slowly at first, and check nothing was lost or leaked.
        peer.socket.resume();
        let length = 0;
        let redactions = 0;
        let leaked = false;
        let reply: Reply | undefined;
        while (!reply) {
          const line = await peer.line(30_000);
          if (line === null) throw new Error("connection ended early");
          const msg = JSON.parse(line) as Reply & { method?: string; params?: { data: string } };
          if (msg.method === "run.output") {
            const data = (msg.params as { data: string }).data;
            length += data.length;
            redactions += data.split("[redacted vault://t]").length - 1;
            leaked ||= data.includes(SECRET);
          } else {
            reply = msg;
          }
        }
        peer.destroy();
        expect(reply.result).toEqual({ exitCode: 0 });
        expect(leaked).toBe(false);
        expect(redactions).toBe(CHUNKS * LINES_PER_CHUNK);
        expect(length).toBe(CHUNKS * LINES_PER_CHUNK * (1000 + "[redacted vault://t]".length + 1));
      },
      60_000,
    );
  });

  describe("stdin backpressure", () => {
    test.runIf(mode === MODES[0])(
      "a child that never reads cannot make the daemon buffer an unbounded stdin",
      async () => {
        const MiB = 1024 * 1024;
        const chunk = b64("x".repeat(512 * 1024)); // 100 of these are 50 MiB
        // Warm up on a child that does read, so the allocator has already grown for this traffic
        // and the baseline below does not include one-off costs.
        const warm = startRun(env.client, { argv: nodeE("process.stdin.resume()") });
        for (let i = 0; i < 20; i++) {
          await env.client.call("run.stdin", { runId: warm.runId, dataB64: chunk });
        }
        await env.client.call("run.stdin", { runId: warm.runId, end: true });
        await warm.result;

        const run = startRun(env.client, {
          argv: nodeE("console.log('up'); setInterval(() => {}, 1000)"),
        });
        await run.seen("stdout", "up");
        const baseline = process.memoryUsage().rss;
        let sent = 0;
        const sender = (async () => {
          for (let i = 0; i < 100; i++) {
            await env.client.call(
              "run.stdin",
              { runId: run.runId, dataB64: chunk },
              { timeoutMs: 0 },
            );
            sent++;
          }
        })();
        sender.catch(() => {});
        let peak = baseline;
        for (let i = 0; i < 25; i++) {
          await new Promise((r) => setTimeout(r, 100));
          peak = Math.max(peak, process.memoryUsage().rss);
        }
        expect(sent).toBeLessThan(10); // stuck behind the full pipe, not 100 chunks in
        expect(peak - baseline).toBeLessThan(20 * MiB);

        // The connection is not stuck behind the pending write: the run can still be ended.
        await env.client.call("run.signal", { runId: run.runId, signal: "SIGKILL" });
        const result = await run.result;
        expect(result.exitCode).not.toBe(0);
        await sender.then(
          () => {},
          () => {}, // "no such run" once it is gone
        );
      },
      60_000,
    );

    test.runIf(mode === MODES[0])(
      "pipelined run.stdin calls are refused while one is waiting, and nothing queues",
      async () => {
        const MiB = 1024 * 1024;
        const warnings = vi.spyOn(process, "emitWarning");
        try {
          const run = startRun(env.client, {
            argv: nodeE("console.log('up'); setInterval(() => {}, 1000)"),
          });
          await run.seen("stdout", "up");
          const big = b64("x".repeat(512 * 1024)); // more than the pipe holds: this one waits
          const small = b64("x".repeat(16 * 1024));
          const baseline = process.memoryUsage().rss;
          const calls = Array.from({ length: 100 }, (_, i) =>
            env.client
              .call(
                "run.stdin",
                { runId: run.runId, dataB64: i === 0 ? big : small },
                { timeoutMs: 0 },
              )
              .then(
                () => "ok",
                (err: unknown) => err,
              ),
          );
          let refused: unknown[] = [];
          for (let i = 0; i < 50 && refused.length < 99; i++) {
            await new Promise((r) => setTimeout(r, 100));
            const settled = await Promise.race([
              Promise.all(calls.slice(1)),
              new Promise<null>((r) => setTimeout(() => r(null), 0)),
            ]);
            if (settled) refused = settled;
          }
          expect(refused).toHaveLength(99);
          for (const err of refused) {
            expect(err).toBeInstanceOf(RpcError);
            expect((err as RpcError).data).toEqual({ name: "RunError" });
            expect((err as RpcError).message).toContain("stdin busy");
          }
          expect(process.memoryUsage().rss - baseline).toBeLessThan(20 * MiB);

          // The first call is still waiting for a child that does not read; the run answers anyway.
          const t0 = Date.now();
          await env.client.call("run.signal", { runId: run.runId, signal: "SIGTERM" });
          expect(Date.now() - t0).toBeLessThan(2000);
          const result = await run.result;
          if (POSIX) expect(result).toEqual({ exitCode: 143, signal: "SIGTERM" });
          else expect(result.exitCode).not.toBe(0);
          expect(await calls[0]).toBe("ok"); // released when the child went away

          expect(
            warnings.mock.calls.filter(
              ([w]) => (w as Error).name === "MaxListenersExceededWarning",
            ),
          ).toEqual([]);
        } finally {
          warnings.mockRestore();
        }
      },
      60_000,
    );
  });

  describe("env file", () => {
    const envFileError = async (file: string) =>
      rpcError(startRun(env.client, { argv: nodeE("0"), cwd: env.dir, envFile: file }).result);

    test.runIf(POSIX)("a FIFO is refused instead of freezing the daemon", async () => {
      const fifo = path.join(env.dir, "fifo.env");
      execFileSync("mkfifo", [fifo]);
      const err = await envFileError(fifo);
      expect(err.data).toEqual({ name: "RunError" });
      expect(err.message).toContain("not a regular file");
      // Still responsive.
      expect(await env.client.call("secret.list")).toEqual([]);
    });

    test("a directory is refused", async () => {
      const err = await envFileError(env.dir);
      expect(err.data).toEqual({ name: "RunError" });
    });

    test("a file over 1 MiB is refused", async () => {
      fs.writeFileSync(path.join(env.dir, "big.env"), `A=${"x".repeat(1024 * 1024)}\n`);
      const err = await envFileError("big.env");
      expect(err.data).toEqual({ name: "RunError" });
      expect(err.message).toContain("larger than");
    });

    test("a missing file is an app error", async () => {
      const err = await envFileError("nope.env");
      expect(err.data).toEqual({ name: "RunError" });
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

  describe("audit of failures", () => {
    const runEvents = async () => (await audit()).filter((e) => e.operation === "run");

    test("a missing secret is logged as an error under its name", async () => {
      await rpcError(
        startRun(env.client, { argv: nodeE("0"), env: { TOKEN: "vault://nope" } }).result,
      );
      const events = await runEvents();
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({ outcome: "error", secretName: "nope" });
    });

    test("a stale grant is logged with its bundle and the missing secret", async () => {
      await put("gone", SECRET);
      await env.client.call("bundle.create", { name: "stale" });
      await env.client.call("bundle.grant", { bundle: "stale", env: "TOKEN", secret: "gone" });
      await env.client.call("secret.remove", { name: "gone" });
      await rpcError(startRun(env.client, { argv: nodeE("0"), bundle: "stale" }).result);
      expect(await runEvents()).toMatchObject([
        { outcome: "error", secretName: "gone", bundle: "stale" },
      ]);
    });

    test("a secret that is too short is logged under its name", async () => {
      await put("tiny", "abc");
      await rpcError(
        startRun(env.client, { argv: nodeE("0"), env: { TOKEN: "vault://tiny" } }).result,
      );
      expect(await runEvents()).toMatchObject([{ outcome: "error", secretName: "tiny" }]);
    });

    test("an unresolvable command is logged as an error", async () => {
      await rpcError(startRun(env.client, { argv: [path.join(env.dir, "missing")] }).result);
      const events = await runEvents();
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({ outcome: "error" });
      expect(events[0]?.secretName).toBeUndefined();
    });

    test("a literal in env is logged as an error, naming the bundle", async () => {
      await env.client.call("bundle.create", { name: "b" });
      const err = await rpcError(
        startRun(env.client, { argv: nodeE("0"), bundle: "b", env: { TOKEN: "literal" } }).result,
      );
      expect(err.code).toBe(-32602);
      expect(await runEvents()).toMatchObject([{ outcome: "error", bundle: "b" }]);
      expect(JSON.stringify(await runEvents())).not.toContain("literal");
    });

    test("params that are not an object name nothing and are not logged", async () => {
      await rpcError(env.client.call("run.start", []));
      expect(await runEvents()).toEqual([]);
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

describe.runIf(POSIX)("the file that was checked is the file that runs", () => {
  test("retargeting a symlink after the check changes nothing", async () => {
    // Its own sandbox: a vault in a temp dir with a throwaway key store.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "avd-"));
    const { vault } = await initVault({
      paths: getPaths({ AGENT_VAULT_HOME: dir }, process.platform),
      store: new MemoryKeyStore(),
    });
    try {
      createBundle(vault, "b");
      allowExe(vault, "b", NODE);
      const link = path.join(dir, "node-link");
      fs.symlinkSync(NODE, link);
      const runId = randomUUID();
      const prepared = prepareRun(vault, {
        runId,
        argv: [link, "-e", "console.log('real node')"],
        cwd: dir,
        baseEnv,
        bundle: "b",
        envFile: undefined,
        refs: undefined,
      });
      // What will be spawned is the real file; the name the caller used is kept for argv[0].
      expect(prepared.command).toBe(fs.realpathSync.native(NODE));
      expect(prepared.argv0).toBe(link);

      // Between the check and the spawn the link is pointed at a different program.
      fs.unlinkSync(link);
      fs.copyFileSync("/bin/sh", link);
      fs.chmodSync(link, 0o755);

      const out: string[] = [];
      const result = await createRunnerService().start(
        runId,
        new Connection(),
        prepared,
        (_method, params) => out.push((params as { data: string }).data),
      );
      expect(result).toEqual({ exitCode: 0 });
      expect(out.join("")).toBe("real node\n");
    } finally {
      vault.close();
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
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

  test("killing a shim's run takes its child process down with it", async () => {
    fs.writeFileSync(
      path.join(env.dir, "idle.js"),
      "console.log(process.pid); setInterval(() => {}, 1000)",
    );
    fs.writeFileSync(path.join(env.dir, "idle.cmd"), `@"${NODE}" "%~dp0idle.js"\r\n`);
    const owner = await connect(env.endpoint);
    const run = startRun(owner, { argv: [path.join(env.dir, "idle.cmd")], cwd: env.dir });
    await run.seen("stdout", "\n");
    const pid = track(Number(run.out.stdout.trim()))[0] as number;
    expect(pidGone(pid)).toBe(false);
    owner.close();
    expect(await waitGone(pid, 6000)).toBe(true);
  });
});
