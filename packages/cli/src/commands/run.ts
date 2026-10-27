import { randomUUID } from "node:crypto";
import path from "node:path";
import type { IpcClient } from "@agent-vault/daemon";
import type { Command } from "commander";
import { PASSPHRASE_ENV } from "../config.js";
import { withDaemon } from "../context.js";
import { CliError, exitWith } from "../errors.js";
import { collect } from "./set.js";

/** Stay well under the daemon's 1 MiB request line once base64 and JSON framing are added. */
const STDIN_SLICE_BYTES = 256 * 1024;

/**
 * `K=vault://x` pairs into the `env` map of `run.start`. A reference is a name, not a secret, so
 * a bad argument is echoed whole.
 */
export function parseEnvRefs(pairs: string[]): Record<string, string> {
  const env: Record<string, string> = {};
  for (const pair of pairs) {
    const eq = pair.indexOf("=");
    if (eq < 1) throw new CliError(`--env expects NAME=vault://secret, got: ${pair}`, 2);
    const name = pair.slice(0, eq);
    if (Object.hasOwn(env, name)) throw new CliError(`--env ${name} given more than once`, 2);
    Object.defineProperty(env, name, {
      value: pair.slice(eq + 1),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return env;
}

/** This process's environment as the child's base. The keyfile passphrase is not handed on. */
function baseEnv(): Record<string, string> {
  const env: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined && key !== PASSPHRASE_ENV) env[key] = value;
  }
  return env;
}

/**
 * Send this process's stdin to the child, one awaited call at a time, then its end. A terminal is
 * not forwarded: the child gets end-of-input at once rather than waiting on keys nobody relays.
 */
async function forwardStdin(client: IpcClient, runId: string): Promise<void> {
  try {
    if (process.stdin.isTTY) {
      await client.call("run.stdin", { runId, end: true });
      return;
    }
    for await (const chunk of process.stdin as AsyncIterable<Buffer>) {
      for (let at = 0; at < chunk.length; at += STDIN_SLICE_BYTES) {
        const dataB64 = chunk.subarray(at, at + STDIN_SLICE_BYTES).toString("base64");
        await client.call("run.stdin", { runId, dataB64 });
      }
    }
    await client.call("run.stdin", { runId, end: true });
  } catch {
    // The child is gone, or stdin is unusable: the run's own result says what happened.
  }
}

type RunOptions = { bundle?: string; envFile?: string; env: string[] };

export function runCommand(program: Command): void {
  program
    .command("run")
    .description("run a command with secrets injected; its output is redacted")
    .usage("[options] -- <command...>")
    .argument("<command...>", "the command and its arguments, after --")
    .option("--bundle <name>", "inject a bundle's secrets")
    .option("--env-file <file>", "env file whose vault:// references are resolved")
    .option(
      "--env <NAME=vault://secret>",
      "inject one secret (repeatable)",
      collect,
      [] as string[],
    )
    .action(async (argv: string[], opts: RunOptions) => {
      const env = parseEnvRefs(opts.env);
      const runId = randomUUID();
      const result = await withDaemon(async (client) => {
        client.onNotification((method, params) => {
          const p = params as { runId?: string; stream?: string; data?: string };
          if (method !== "run.output" || p.runId !== runId || typeof p.data !== "string") return;
          (p.stream === "stderr" ? process.stderr : process.stdout).write(p.data);
        });
        // The first signal goes to the child as it came, the second asks harder (SIGTERM), the
        // third gives up: the CLI leaves and the daemon, seeing the connection drop, ends the tree.
        let signals = 0;
        const relay = (signal: "SIGINT" | "SIGTERM") => () => {
          signals++;
          if (signals >= 3) {
            void exitWith(130);
            return;
          }
          const sent = signals === 1 ? signal : "SIGTERM";
          client.call("run.signal", { runId, signal: sent }).catch(() => {});
        };
        const onInt = relay("SIGINT");
        const onTerm = relay("SIGTERM");
        process.on("SIGINT", onInt);
        process.on("SIGTERM", onTerm);
        try {
          // The run is registered before the daemon reads the next request, so stdin can follow.
          const started = client.call<{ exitCode: number }>(
            "run.start",
            {
              runId,
              argv,
              cwd: process.cwd(),
              baseEnv: baseEnv(),
              ...(opts.bundle !== undefined && { bundle: opts.bundle }),
              ...(opts.envFile !== undefined && { envFile: path.resolve(opts.envFile) }),
              ...(Object.keys(env).length > 0 && { env }),
            },
            { timeoutMs: 0 },
          );
          void forwardStdin(client, runId);
          return await started;
        } finally {
          process.off("SIGINT", onInt);
          process.off("SIGTERM", onTerm);
        }
      });
      // Not a return: stdin may still be open, and the exit code is the child's.
      await exitWith(result.exitCode);
    });
}
