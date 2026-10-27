import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { isSea } from "node:sea";
import { setTimeout as sleep } from "node:timers/promises";
import { ipcEndpoint, type VaultPaths } from "@agent-vault/platform";
import { connect, type IpcClient } from "./client.js";
import { DaemonExitedError, DaemonIdentityError } from "./errors.js";
import { lockPath } from "./lock.js";

const RETRY_INTERVAL_MS = 100;

/**
 * How long a cold start may take. On Windows a start runs `icacls` four times (two per private dir,
 * 150-500 ms each on a CI runner) on top of node's own start-up: 1.9 s in total on a quiet runner,
 * past 3 s when other test files compete for the CPU.
 */
export const defaultTimeoutMs = (platform: NodeJS.Platform = process.platform): number =>
  platform === "win32" ? 10_000 : 3000;

export type EnsureDaemonOptions = {
  /** Command that runs the daemon. Default: the running CLI's `daemon run`. */
  spawnArgv?: string[] | undefined;
  /** How long to wait for a spawned daemon. Default `defaultTimeoutMs()`: 3000, 10000 on Windows. */
  timeoutMs?: number | undefined;
  /**
   * Bytes (plus a newline) to write to the spawned daemon's stdin, which is then closed; the
   * buffer is zeroed afterwards. This is how a secret such as the keyfile passphrase reaches a
   * daemon without sitting in its environment for its whole life, where any process of the same
   * user can read it. Setting it adds `--passphrase-stdin` to the default argv.
   */
  stdinPayload?: Uint8Array | undefined;
  /** Appended to the default argv (`--recovering`). Ignored with an explicit `spawnArgv`. */
  extraArgs?: string[] | undefined;
  /** Called with the pid of the daemon this call spawned, if it spawned one. */
  onSpawn?: ((pid: number | undefined) => void) | undefined;
  /** The spawned daemon's environment. Default: this process's. */
  env?: NodeJS.ProcessEnv | undefined;
};

export type DaemonRunArgvOptions = {
  sea?: boolean | undefined;
  execPath?: string | undefined;
  /** The script node was started with (`process.argv[1]`); unused in a SEA binary. */
  entry?: string | undefined;
};

/**
 * The CLI that is running now, asked to run the daemon (Task 14 provides `daemon run`): node plus
 * the script, or, in a SEA binary, the binary alone (it has no script, and `process.argv[1]` is
 * not one). Absolute and symlink-resolved, so it stays valid when the caller's cwd is gone.
 */
export function daemonRunArgv(opts: DaemonRunArgvOptions = {}): string[] {
  const resolveReal = (file: string): string => {
    try {
      return fs.realpathSync(file);
    } catch {
      return path.resolve(file);
    }
  };
  const execPath = opts.execPath ?? process.execPath;
  if (opts.sea ?? isSea()) return [resolveReal(execPath), "daemon", "run"];
  const entry = "entry" in opts ? opts.entry : process.argv[1];
  if (!entry) throw new Error("cannot tell which CLI to spawn: process.argv[1] is empty");
  return [execPath, resolveReal(entry), "daemon", "run"];
}

/**
 * Connect to vaultd, starting it first if nobody answers: spawn it detached, then retry every
 * 100 ms for up to `timeoutMs`.
 */
export async function ensureDaemon(
  paths: VaultPaths,
  opts: EnsureDaemonOptions = {},
): Promise<IpcClient> {
  const endpoint = ipcEndpoint(paths);
  try {
    return await connect(endpoint);
  } catch {
    // Not running (or not answering): start one below.
  }

  const payload = opts.stdinPayload;
  const [cmd, ...args] = opts.spawnArgv ?? [
    ...daemonRunArgv(),
    ...(payload !== undefined ? ["--passphrase-stdin"] : []),
    ...(opts.extraArgs ?? []),
  ];
  if (!cmd) throw new Error("spawnArgv is empty");
  const timeoutMs = opts.timeoutMs ?? defaultTimeoutMs();
  const child = spawn(cmd, args, {
    detached: true,
    stdio: [payload ? "pipe" : "ignore", "ignore", "ignore"],
    windowsHide: true,
    ...(opts.env !== undefined && { env: opts.env }),
  });
  opts.onSpawn?.(child.pid);
  if (payload) {
    const line = Buffer.concat([payload, Buffer.from("\n")]);
    child.stdin?.on("error", () => {}); // EPIPE if the daemon is already gone
    child.stdin?.end(line, () => line.fill(0));
    payload.fill(0);
  }
  let spawnError: Error | undefined;
  child.on("error", (err) => {
    spawnError = err;
  });
  // An exit with code 0 means the child lost the race to another daemon: keep trying to connect.
  // Any other exit before a connect succeeds is a failed start.
  let failedExit: string | undefined;
  let failedCode: number | null = null;
  child.on("exit", (code, signal) => {
    if (code === 0) return;
    failedExit = code === null ? `signal ${signal}` : `code ${code}`;
    failedCode = code;
  });
  child.unref();

  const deadline = Date.now() + timeoutMs;
  let last: unknown;
  while (Date.now() < deadline) {
    await sleep(RETRY_INTERVAL_MS);
    if (spawnError) throw new Error("could not start vaultd", { cause: spawnError });
    try {
      return await connect(endpoint, { timeoutMs: Math.max(1, deadline - Date.now()) });
    } catch (err) {
      last = err;
    }
    // Checked after the connect attempt: another instance may have come up while this one failed.
    if (failedExit) {
      throw new DaemonExitedError(
        `vaultd exited with ${failedExit} before it started; if a stale lock is the cause, delete ${lockPath(paths.runtimeDir)}`,
        failedCode,
      );
    }
  }
  if (last instanceof DaemonIdentityError) throw last;
  // A child that exits 0 because a stale lock names a reused pid ends up here.
  const lock = lockPath(paths.runtimeDir);
  const hint = fs.existsSync(lock)
    ? `; vaultd.lock exists at ${lock}; if no daemon is running, delete it`
    : "";
  throw new Error(`vaultd did not start within ${timeoutMs} ms${hint}`, { cause: last });
}
