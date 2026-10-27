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

/** `K=vault://x` pairs into the `env` map of `run.start`. */
export function parseEnvRefs(pairs: string[]): Record<string, string> {
  const env: Record<string, string> = {};
  for (const pair of pairs) {
    const eq = pair.indexOf("=");
    if (eq < 1)
      throw new CliError(`--env expects NAME=vault://secret, got: ${pair.split("=")[0]}`, 2);
    Object.defineProperty(env, pair.slice(0, eq), {
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

/** Send this process's stdin to the child, one awaited call at a time, then its end. */
async function forwardStdin(client: IpcClient, runId: string): Promise<void> {
  try {
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
        const relay = (signal: "SIGINT" | "SIGTERM") => () => {
          client.call("run.signal", { runId, signal }).catch(() => {});
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
