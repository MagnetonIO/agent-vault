import type { ChildProcess } from "node:child_process";
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
export function prepareRun(vault: Vault, p: RunParams): PreparedRun {
  const argv0 = p.argv[0] as string;
  const bundle = p.bundle === undefined ? undefined : resolveBundle(vault, p.bundle);

  const command = resolveExecutable(argv0, p.cwd, p.baseEnv);
  if (command === undefined) throw new RunError(`command not found: ${argv0}`);
  if (bundle && bundle.exes.length > 0) {
    const real = realpathOrUndefined(command);
    if (real === undefined) throw new RunError(`command not found: ${argv0}`);
    const allowed = bundle.exes.some((exe) => {
      const allowedReal = realpathOrUndefined(exe);
      return allowedReal !== undefined && canon(allowedReal) === canon(real);
    });
    if (!allowed) throw new ExeNotAllowedError(real);
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
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      throw new RunError(`could not read env file ${file}`);
    }
    for (const entry of parseEnvFile(text)) {
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
      values.set(slot.secret, readSecretText(vault, slot.secret));
    }
  }
  const secrets = [...values].map(([name, value]) => ({ name, value }));
  let redactors: PreparedRun["redactors"];
  try {
    redactors = { stdout: createRedactor(secrets), stderr: createRedactor(secrets) };
  } catch (err) {
    // The message names the secret that is too short, never its value.
    if (err instanceof RangeError) throw new RunError(err.message);
    throw err;
  }
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
  /** Write to or end the child's stdin. Only the connection that started the run may. */
  stdin(owner: Connection, runId: string, data: Buffer | undefined, end: boolean): void;
  /** Send a signal to the child. Only the connection that started the run may. */
  signal(owner: Connection, runId: string, signal: NodeJS.Signals): void;
  /** SIGTERM every child, SIGKILL the ones still alive after KILL_GRACE_MS, wait for them. */
  close(): Promise<void>;
};

const hasExited = (child: ChildProcess): boolean =>
  child.exitCode !== null || child.signalCode !== null;

/** SIGTERM now, SIGKILL after the grace period if it is still running. */
function terminate(entry: Active): void {
  const { child } = entry;
  if (hasExited(child)) return;
  child.kill("SIGTERM");
  entry.killTimer ??= setTimeout(() => {
    if (!hasExited(child)) child.kill("SIGKILL");
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
        child = spawn(run.command, run.args, {
          cwd: run.cwd,
          env: run.env,
          stdio: ["pipe", "pipe", "pipe"],
          windowsHide: true,
          ...(!WIN && { argv0: run.argv0 }),
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
      entry.unwatch = owner.onClose(() => terminate(entry));
      const forget = () => {
        entry.unwatch();
        clearTimeout(entry.killTimer);
        if (active.get(runId) === entry) active.delete(runId);
      };

      const output = (stream: "stdout" | "stderr") => (data: string) => {
        if (data !== "") notify("run.output", { runId, stream, data });
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
      if (!stdin || stdin.destroyed || !stdin.writable) return;
      if (data && data.length > 0) stdin.write(data);
      if (end) stdin.end();
    },

    signal(owner, runId, signal) {
      owned(owner, runId).child.kill(signal);
    },

    async close() {
      closed = true;
      const entries = [...active.values()];
      for (const entry of entries) terminate(entry);
      await Promise.all(entries.map((e) => e.exited));
    },
  };
}
