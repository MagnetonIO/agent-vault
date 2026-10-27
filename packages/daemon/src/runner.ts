import { type ChildProcess, spawn as spawnDirect } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Readable } from "node:stream";
import { StringDecoder } from "node:string_decoder";
import { parseEnvFile, resolveBundle, type Vault } from "@agent-vault/core";
import { createRedactor, type Redactor } from "@agent-vault/detect";
import spawn from "cross-spawn";
import type { Connection } from "./connection.js";
import { ExeNotAllowedError, RunError } from "./errors.js";
import { decodeSecretText } from "./secret-text.js";

/** How long a child that was sent SIGTERM may keep running before it is killed outright. */
export const KILL_GRACE_MS = 5000;

const WIN = process.platform === "win32";

/** A validated `run.start`. `refs` maps env names to secret names (the `vault://` part is gone). */
export type RunParams = {
  runId: string;
  argv: string[];
  cwd: string;
  baseEnv: Record<string, string>;
  bundle: string | undefined;
  envFile: string | undefined;
  refs: Record<string, string> | undefined;
};

/** A run that is ready to start. `env` holds secret values: it goes to the child and nowhere else. */
export type PreparedRun = {
  command: string;
  argv0: string;
  args: string[];
  cwd: string;
  env: Record<string, string>;
  /** Each secret that is in `env`, once. These are what gets audited. */
  secretNames: string[];
  bundle: string | undefined;
  redactors: { stdout: Redactor; stderr: Redactor };
};

export type RunResult = { exitCode: number; signal?: string };

/** An env var by name; Windows names are case-insensitive. */
function envGet(env: Record<string, string>, key: string): string | undefined {
  if (!WIN) return env[key];
  const found = Object.keys(env).find((k) => k.toUpperCase() === key);
  return found === undefined ? undefined : env[found];
}

function isExecutable(file: string): boolean {
  try {
    if (!fs.statSync(file).isFile()) return false;
    if (!WIN) fs.accessSync(file, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

/**
 * The file `command` names, searched the way a shell would: a path (absolute or with a separator)
 * is taken relative to `cwd`, a bare name is looked up in `env.PATH` (on Windows also in `cwd`,
 * trying each `PATHEXT` extension). Undefined if there is no such executable.
 */
export function resolveExecutable(
  command: string,
  cwd: string,
  env: Record<string, string>,
): string | undefined {
  const isPath =
    command.includes("/") || (WIN && command.includes("\\")) || path.isAbsolute(command);
  const dirs = isPath
    ? [""]
    : [
        ...(WIN ? [cwd] : []),
        ...(envGet(env, "PATH") ?? "").split(path.delimiter).filter((d) => d !== ""),
      ];
  const names = WIN
    ? [
        ...(command.includes(".") ? [command] : []),
        ...(envGet(env, "PATHEXT") ?? ".COM;.EXE;.BAT;.CMD")
          .split(";")
          .filter((e) => e !== "")
          .map((e) => command + e),
      ]
    : [command];
  for (const dir of dirs) {
    for (const name of names) {
      const candidate = path.resolve(cwd, dir, name);
      if (isExecutable(candidate)) return candidate;
    }
  }
  return undefined;
}

const canon = (p: string): string => (WIN ? p.toLowerCase() : p);

function realpathOrUndefined(p: string): string | undefined {
  try {
    return fs.realpathSync.native(p);
  } catch {
    return undefined;
  }
}

type Slot = { secret: string } | { literal: string };

/** Largest env file `run.start` will read. */
export const ENV_FILE_MAX_BYTES = 1024 * 1024;

/**
 * The text of a regular file of at most ENV_FILE_MAX_BYTES. It is opened without blocking and
 * checked through the descriptor, so a FIFO or device cannot hold the daemon (opening a FIFO for
 * reading would otherwise wait for a writer) and the file cannot change type after the check.
 */
function readEnvFile(file: string): string {
  let fd: number | undefined;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NONBLOCK ?? 0));
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new RunError(`env file is not a regular file: ${file}`);
    if (st.size > ENV_FILE_MAX_BYTES) {
      throw new RunError(`env file is larger than ${ENV_FILE_MAX_BYTES} bytes: ${file}`);
    }
    const buf = Buffer.alloc(st.size);
    let read = 0;
    while (read < buf.length) {
      const n = fs.readSync(fd, buf, read, buf.length - read, read);
      if (n === 0) break;
      read += n;
    }
    return buf.toString("utf8", 0, read);
  } catch (err) {
    if (err instanceof RunError) throw err;
    throw new RunError(`could not read env file ${file}`);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

/** Filled in by `prepareRun` with the secret it was working on, so a failure can be audited. */
export type FailedAt = { secretName?: string | undefined };

/** The secret as an env var value: UTF-8 text without NUL. The decrypted bytes are zeroed. */
function readSecretText(vault: Vault, name: string): string {
  const bytes = vault.readValue(name);
  try {
    const text = decodeSecretText(name, bytes);
    if (text.includes("\0")) {
      throw new RunError(
        `secret ${name} contains a NUL byte and cannot be an environment variable`,
      );
    }
    return text;
  } finally {
    bytes.fill(0);
  }
}

/**
 * Check the executable against the bundle's list, work out the child's environment and build the
 * redactors. Decrypts nothing before the executable is allowed. Throws ExeNotAllowedError,
 * SecretNotFoundError, BundleNotFoundError or RunError, none of which carry a secret value.
 *
 * The child is started from the path that was checked, so a `PATH` set by a grant or an env file
 * cannot send it to a different program than the one the allowlist saw.
 */
export function prepareRun(vault: Vault, p: RunParams, at: FailedAt = {}): PreparedRun {
  const argv0 = p.argv[0] as string;
  const bundle = p.bundle === undefined ? undefined : resolveBundle(vault, p.bundle);

  let command = resolveExecutable(argv0, p.cwd, p.baseEnv);
  if (command === undefined) throw new RunError(`command not found: ${argv0}`);
  if (bundle && bundle.exes.length > 0) {
    const real = realpathOrUndefined(command);
    if (real === undefined) throw new RunError(`command not found: ${argv0}`);
    const allowed = bundle.exes.some((exe) => {
      const allowedReal = realpathOrUndefined(exe);
      return allowedReal !== undefined && canon(allowedReal) === canon(real);
    });
    if (!allowed) throw new ExeNotAllowedError(real);
    // Start exactly the file that was checked, not a path (a symlink) that could be retargeted
    // before the spawn. `argv0` below keeps the name the caller used.
    command = real;
  }

  // Lowest layer first; a later layer replaces the same name from an earlier one.
  const plan = new Map<string, Slot>();
  const set = (key: string, slot: Slot) => {
    if (WIN) {
      for (const k of plan.keys())
        if (k !== key && k.toUpperCase() === key.toUpperCase()) plan.delete(k);
    }
    plan.set(key, slot);
  };
  for (const [key, literal] of Object.entries(p.baseEnv)) set(key, { literal });
  for (const [key, secret] of Object.entries(bundle?.env ?? {})) set(key, { secret });
  if (p.envFile !== undefined) {
    const file = path.resolve(p.cwd, p.envFile);
    for (const entry of parseEnvFile(readEnvFile(file))) {
      if (entry.ref !== undefined) {
        set(entry.key, { secret: entry.ref });
      } else {
        const literal = entry.literal ?? "";
        if (literal.includes("\0")) throw new RunError(`env var ${entry.key} contains a NUL byte`);
        set(entry.key, { literal });
      }
    }
  }
  for (const [key, secret] of Object.entries(p.refs ?? {})) set(key, { secret });

  const values = new Map<string, string>();
  for (const slot of plan.values()) {
    if ("secret" in slot && !values.has(slot.secret)) {
      at.secretName = slot.secret;
      values.set(slot.secret, readSecretText(vault, slot.secret));
      at.secretName = undefined;
    }
  }
  const secrets = [...values].map(([name, value]) => ({ name, value }));
  for (const s of secrets) {
    try {
      createRedactor([s]);
    } catch (err) {
      // The message names the secret that is too short, never its value.
      at.secretName = s.name;
      if (err instanceof RangeError) throw new RunError(err.message);
      throw err;
    }
  }
  const redactors = { stdout: createRedactor(secrets), stderr: createRedactor(secrets) };
  const env = Object.fromEntries(
    [...plan].map(([key, slot]) => [
      key,
      "literal" in slot ? slot.literal : (values.get(slot.secret) as string),
    ]),
  );
  return {
    command,
    argv0,
    args: p.argv.slice(1),
    cwd: p.cwd,
    env,
    secretNames: [...values.keys()],
    bundle: p.bundle,
    redactors,
  };
}

type Active = {
  child: ChildProcess;
  owner: Connection;
  /** Resolves when the process has exited (its output may still be flushing). */
  exited: Promise<void>;
  killTimer: NodeJS.Timeout | undefined;
  /** Stops watching the owner's connection. */
  unwatch: () => void;
};

export type RunnerService = {
  has(runId: string): boolean;
  /**
   * Spawn and register the run synchronously (so a `run.stdin` that follows on the same
   * connection finds it), then resolve once the child has exited and both streams are flushed.
   * Rejects with RunError if the child cannot be started.
   */
  start(
    runId: string,
    owner: Connection,
    run: PreparedRun,
    notify: (method: string, params: unknown) => void,
  ): Promise<RunResult>;
  /**
   * Write to or end the child's stdin. Only the connection that started the run may. Resolves once
   * the child's stdin has taken the data (drained), the stream has finished or closed, or the
   * child is gone, so a client that awaits each call never gets ahead of a child that is not
   * reading.
   */
  stdin(owner: Connection, runId: string, data: Buffer | undefined, end: boolean): Promise<void>;
  /** Send a signal to the child. Only the connection that started the run may. */
  signal(owner: Connection, runId: string, signal: NodeJS.Signals): void;
  /** SIGTERM every child tree, SIGKILL what is left after KILL_GRACE_MS, wait for them to go. */
  close(): Promise<void>;
};

const hasExited = (child: ChildProcess): boolean =>
  child.exitCode !== null || child.signalCode !== null;

/** True while the child, or on POSIX anything left in its process group, is still running. */
function treeAlive(child: ChildProcess): boolean {
  if (WIN || child.pid === undefined) return !hasExited(child);
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Signal the child and everything it started. POSIX: the child leads its own process group (see
 * `detached` below), so the signal goes to `-pgid`. Windows has no groups: SIGTERM and SIGKILL run
 * `taskkill /T /F` on the pid (no shell); a SIGINT cannot be delivered and is plain `kill`.
 */
function signalTree(child: ChildProcess, signal: NodeJS.Signals): void {
  const { pid } = child;
  if (pid === undefined) return;
  if (!WIN) {
    try {
      process.kill(-pid, signal);
    } catch {
      child.kill(signal); // the group is already gone
    }
    return;
  }
  if (signal === "SIGINT") {
    child.kill(signal);
    return;
  }
  const root = process.env.SystemRoot ?? process.env.windir ?? "C:\\Windows";
  const taskkill = path.win32.join(root, "System32", "taskkill.exe");
  try {
    const killer = spawnDirect(taskkill, ["/PID", String(pid), "/T", "/F"], {
      stdio: "ignore",
      windowsHide: true,
    });
    killer.on("error", () => child.kill(signal));
  } catch {
    child.kill(signal);
  }
}

/** SIGTERM the tree now; SIGKILL whatever is left of it after the grace period. */
function terminate(entry: Active): void {
  const { child } = entry;
  if (entry.killTimer !== undefined || !treeAlive(child)) return;
  signalTree(child, "SIGTERM");
  // Not cleared when the child exits: its descendants may have ignored the SIGTERM.
  entry.killTimer = setTimeout(() => {
    if (treeAlive(child)) signalTree(child, "SIGKILL");
  }, KILL_GRACE_MS);
  entry.killTimer.unref();
}

export function createRunnerService(): RunnerService {
  const active = new Map<string, Active>();
  let closed = false;

  /** The run, if `owner` started it. A run that is not yours looks the same as one that is not there. */
  const owned = (owner: Connection, runId: string): Active => {
    const entry = active.get(runId);
    if (!entry || entry.owner !== owner) throw new RunError("no such run");
    return entry;
  };

  /** Redact `stream` and send it on; resolves after the final flush. */
  function pipeOutput(
    stream: Readable,
    redactor: Redactor,
    send: (data: string) => void,
  ): Promise<void> {
    const decoder = new StringDecoder("utf8");
    return new Promise<void>((resolve) => {
      stream.on("data", (chunk: Buffer) => send(redactor.push(decoder.write(chunk))));
      stream.once("close", () => {
        send(redactor.push(decoder.end()) + redactor.flush());
        resolve();
      });
      stream.on("error", () => {});
    });
  }

  return {
    has: (runId) => active.has(runId),

    start(runId, owner, run, notify) {
      if (closed) throw new RunError("vaultd is shutting down");
      if (active.has(runId)) throw new RunError("run id already in use");

      let child: ChildProcess;
      try {
        // cross-spawn escapes arguments for cmd.exe when `command` is a .cmd/.bat shim, with one
        // known gap: a `%` in an argument is expanded by cmd.exe and is not escaped.
        child = spawn(run.command, run.args, {
          cwd: run.cwd,
          env: run.env,
          stdio: ["pipe", "pipe", "pipe"],
          windowsHide: true,
          // Its own process group on POSIX, so signals reach everything it starts.
          ...(!WIN && { detached: true, argv0: run.argv0 }),
        });
      } catch {
        // Node's own message can quote the environment, which holds secret values.
        throw new RunError("could not start the command");
      }
      const { stdin, stdout, stderr } = child;
      if (!stdin || !stdout || !stderr) {
        child.kill("SIGKILL");
        throw new RunError("could not start the command");
      }
      stdin.on("error", () => {}); // EPIPE once the child is gone
      child.on("error", () => {}); // a failed kill; start failures are handled below

      const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
        (resolve) => child.once("exit", (code, signal) => resolve({ code, signal })),
      );
      const entry: Active = {
        child,
        owner,
        exited: exited.then(() => {}),
        killTimer: undefined,
        unwatch: () => {},
      };
      active.set(runId, entry);
      // From here the owner's connection decides how long the child lives.
      let paused = false;
      const resumeOutput = () => {
        paused = false;
        stdout.resume();
        stderr.resume();
      };
      entry.unwatch = owner.onClose(() => {
        terminate(entry);
        resumeOutput(); // nobody is reading; let the streams run dry so the run can finish
      });
      const forget = () => {
        entry.unwatch();
        if (active.get(runId) === entry) active.delete(runId);
      };

      const output = (stream: "stdout" | "stderr") => (data: string) => {
        if (data === "") return;
        notify("run.output", { runId, stream, data });
        // A client that is not reading must not make the daemon buffer the child's output: stop
        // reading the child (its pipe fills and it blocks) until the socket has drained.
        if (!paused && owner.blocked) {
          paused = true;
          stdout.pause();
          stderr.pause();
          owner.onceDrained(resumeOutput);
        }
      };
      const flushed = Promise.all([
        pipeOutput(stdout, run.redactors.stdout, output("stdout")),
        pipeOutput(stderr, run.redactors.stderr, output("stderr")),
      ]);

      return new Promise<RunResult>((resolve, reject) => {
        child.once("error", (err: NodeJS.ErrnoException) => {
          if (child.pid !== undefined) return; // not a start failure
          forget();
          reject(new RunError(`could not start the command (${err.code ?? "error"})`));
        });
        child.once("spawn", () => {
          Promise.all([exited, flushed]).then(([{ code, signal }]) => {
            forget();
            if (signal) {
              resolve({ exitCode: 128 + (os.constants.signals[signal] ?? 0), signal });
            } else {
              resolve({ exitCode: code ?? 1 });
            }
          });
        });
      });
    },

    stdin(owner, runId, data, end) {
      const { child } = owned(owner, runId);
      const { stdin } = child;
      if (!stdin || stdin.destroyed || !stdin.writable) return Promise.resolve();
      const accepted = data && data.length > 0 ? stdin.write(data) : true;
      if (end) stdin.end();
      if (accepted) return Promise.resolve();
      return new Promise<void>((resolve) => {
        const events = ["drain", "finish", "close", "error"] as const;
        const done = () => {
          for (const event of events) stdin.off(event, done);
          child.off("exit", done);
          resolve();
        };
        for (const event of events) stdin.once(event, done);
        child.once("exit", done);
      });
    },

    signal(owner, runId, signal) {
      signalTree(owned(owner, runId).child, signal);
    },

    async close() {
      closed = true;
      const entries = [...active.values()];
      const deadline = Date.now() + KILL_GRACE_MS;
      for (const entry of entries) terminate(entry);
      await Promise.all(
        entries.map(async ({ child, exited }) => {
          await exited;
          // The child is gone; give what it started the rest of the grace, then kill it.
          while (treeAlive(child) && Date.now() < deadline) {
            await new Promise((resolve) => setTimeout(resolve, 25));
          }
          if (treeAlive(child)) signalTree(child, "SIGKILL");
        }),
      );
    },
  };
}
