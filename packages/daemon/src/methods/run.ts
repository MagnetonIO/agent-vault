import path from "node:path";
import { appendAudit, isValidEnvName, isValidName, parseRef, type Vault } from "@agent-vault/core";
import { deviceId, type Harness, harnessOf } from "../device.js";
import { ExeNotAllowedError, RunError } from "../errors.js";
import { type FailedAt, type PreparedRun, prepareRun, type RunParams } from "../runner.js";
import { invalid, optName, optString, paramsObject, reqBase64, reqString } from "./params.js";
import type { Registry } from "./types.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SIGNALS = ["SIGINT", "SIGTERM", "SIGKILL"] as const;

type Params = Record<string, unknown>;

const hasNul = (s: string): boolean => s.includes("\0");

function reqRunId(p: Params): string {
  const runId = reqString(p, "runId");
  if (!UUID_RE.test(runId)) throw invalid("runId", "must be a UUID");
  return runId;
}

/** A plain object of strings; `rule` says what is wrong when it is not. Values are never echoed. */
function stringMap(v: unknown, field: string, rule: string): Record<string, string> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw invalid(field, rule);
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(v)) {
    // A name may start with "=" (Windows keeps `=C:` style entries) but has no other "=" or NUL.
    if (key === "" || hasNul(key) || key.indexOf("=", 1) !== -1) throw invalid(field, rule);
    if (typeof value !== "string" || hasNul(value)) throw invalid(field, rule);
    Object.defineProperty(out, key, {
      value,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

function parseStart(params: unknown): RunParams {
  const p = paramsObject(params, [
    "runId",
    "argv",
    "cwd",
    "baseEnv",
    "bundle",
    "envFile",
    "env",
    "harness",
  ]);
  const argv = p.argv;
  if (
    !Array.isArray(argv) ||
    argv.length === 0 ||
    argv.some((a) => typeof a !== "string" || hasNul(a)) ||
    argv[0] === ""
  ) {
    throw invalid("argv", "must be a non-empty array of strings starting with the command");
  }
  const cwd = reqString(p, "cwd");
  if (hasNul(cwd) || !path.isAbsolute(cwd)) throw invalid("cwd", "must be an absolute path");
  const envFile = optString(p, "envFile");
  if (envFile !== undefined && hasNul(envFile)) throw invalid("envFile", "must be a path");

  let refs: Record<string, string> | undefined;
  if (p.env !== undefined) {
    const rule = "must map names to vault:// references";
    refs = {};
    for (const [key, value] of Object.entries(stringMap(p.env, "env", rule))) {
      const secret = parseRef(value);
      if (!isValidEnvName(key) || secret === null) throw invalid("env", rule);
      Object.defineProperty(refs, key, {
        value: secret,
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
  }
  return {
    runId: reqRunId(p),
    argv: argv as string[],
    cwd,
    baseEnv: stringMap(p.baseEnv, "baseEnv", "must be an object of strings"),
    bundle: optName(p, "bundle"),
    envFile,
    refs,
  };
}

/** One audit event for `run`. Names only. */
function record(
  vault: Vault,
  harness: Harness,
  outcome: "brokered" | "blocked" | "error",
  fields: { secretName?: string | undefined; bundle?: string | undefined },
): void {
  appendAudit(vault, {
    deviceId,
    harness,
    actor: "rpc",
    ...(fields.secretName !== undefined && { secretName: fields.secretName }),
    ...(fields.bundle !== undefined && { bundle: fields.bundle }),
    operation: "run",
    outcome,
  });
}

/** Log `outcome` without letting a failed append hide the error the caller is about to get. */
function recordQuietly(...args: Parameters<typeof record>): void {
  try {
    record(...args);
  } catch {
    // The original error is the one the caller needs.
  }
}

/**
 * These write their own audit events (one per injected secret), so they are not `mutates`.
 * None returns secret bytes: the child's output is redacted before it is sent.
 */
export const runMethods: Registry = {
  "run.start": {
    mutates: false,
    returnsSecret: false,
    handler: async (ctx, params) => {
      // Everything up to the spawn is synchronous: the run is registered before the daemon reads
      // the connection's next request, so a `run.stdin` sent right behind this one finds it.
      const harness = harnessOf(params);
      const vault = ctx.vault();

      let p: RunParams;
      try {
        p = parseStart(params);
      } catch (err) {
        // Logged unless the params are not even an object, i.e. there is nothing to name.
        if (typeof params === "object" && params !== null && !Array.isArray(params)) {
          const bundle = (params as Params).bundle;
          recordQuietly(vault, harness, "error", {
            bundle: isValidName(bundle) ? bundle : undefined,
          });
        }
        throw err;
      }
      const at: FailedAt = {};
      let prepared: PreparedRun;
      try {
        if (ctx.runner.has(p.runId)) throw new RunError("run id already in use");
        prepared = prepareRun(vault, p, at);
      } catch (err) {
        recordQuietly(vault, harness, err instanceof ExeNotAllowedError ? "blocked" : "error", {
          bundle: p.bundle,
          secretName: at.secretName,
        });
        throw err;
      }
      // Logged before the child exists: if the log cannot be written, nothing is handed over.
      for (const secretName of prepared.secretNames) {
        record(vault, harness, "brokered", { secretName, bundle: prepared.bundle });
      }
      try {
        return await ctx.runner.start(p.runId, ctx.connection, prepared, ctx.notify);
      } catch (err) {
        recordQuietly(vault, harness, "error", { bundle: prepared.bundle });
        throw err;
      }
    },
  },
  "run.stdin": {
    mutates: false,
    returnsSecret: false,
    handler: async (ctx, params) => {
      // The reply waits until the child has taken the data: a client that awaits each call cannot
      // get ahead of a child that is not reading. (A client that does not await can have at most
      // MAX_IN_FLIGHT requests queued.)
      const p = paramsObject(params, ["runId", "dataB64", "end"]);
      const runId = reqRunId(p);
      const data = p.dataB64 === undefined ? undefined : reqBase64(p, "dataB64");
      if (p.end !== undefined && typeof p.end !== "boolean")
        throw invalid("end", "must be a boolean");
      await ctx.runner.stdin(ctx.connection, runId, data, p.end === true);
      return { ok: true };
    },
  },
  "run.signal": {
    mutates: false,
    returnsSecret: false,
    handler: (ctx, params) => {
      const p = paramsObject(params, ["runId", "signal"]);
      const runId = reqRunId(p);
      const signal = p.signal;
      if (!(SIGNALS as readonly unknown[]).includes(signal)) {
        throw invalid("signal", `must be one of ${SIGNALS.join(", ")}`);
      }
      ctx.runner.signal(ctx.connection, runId, signal as (typeof SIGNALS)[number]);
      return { ok: true };
    },
  },
};
