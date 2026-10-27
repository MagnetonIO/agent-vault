import { RpcError } from "../errors.js";
import { ERR } from "../rpc.js";

/** Same rule as the vault's secret names (global constraints); bundles use it too. */
const NAME_RE = /^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*)*$/;
const NAME_MAX = 128;
const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const KEY_ECHO_RE = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;

export const isValidName = (name: unknown): name is string =>
  typeof name === "string" && name.length <= NAME_MAX && NAME_RE.test(name);

/** Messages name the field and the rule, never the offending value. */
export const invalid = (field: string, rule: string): RpcError =>
  new RpcError(ERR.INVALID_PARAMS, `invalid params: ${field} ${rule}`);

type Params = Record<string, unknown>;

/**
 * `params` as an object whose keys are all in `allowed`. A missing `params` is `{}`. An unknown
 * key is rejected so a client that sends `value` for `valueB64` fails instead of being ignored.
 */
export function paramsObject(params: unknown, allowed: readonly string[]): Params {
  if (params === undefined) return {};
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw invalid("params", "must be an object");
  }
  for (const key of Object.keys(params)) {
    if (!allowed.includes(key)) {
      throw invalid(KEY_ECHO_RE.test(key) ? `"${key}"` : "a field", "is not accepted");
    }
  }
  return params as Params;
}

export function optString(p: Params, key: string): string | undefined {
  const v = p[key];
  if (v === undefined) return undefined;
  if (typeof v !== "string" || v.length === 0) throw invalid(key, "must be a non-empty string");
  return v;
}

export function reqString(p: Params, key: string): string {
  const v = optString(p, key);
  if (v === undefined) throw invalid(key, "is required");
  return v;
}

export function optInt(p: Params, key: string, min: number, max: number): number | undefined {
  const v = p[key];
  if (v === undefined) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v) || v < min || v > max) {
    throw invalid(key, `must be an integer from ${min} to ${max}`);
  }
  return v;
}

export function optName(p: Params, key: string): string | undefined {
  const v = p[key];
  if (v === undefined) return undefined;
  if (!isValidName(v)) throw invalid(key, "is not a valid name");
  return v;
}

export function reqName(p: Params, key: string): string {
  const v = optName(p, key);
  if (v === undefined) throw invalid(key, "is required");
  return v;
}

export function optTags(p: Params, key: string): string[] | undefined {
  const v = p[key];
  if (v === undefined) return undefined;
  if (!Array.isArray(v) || v.some((t) => typeof t !== "string" || t.length === 0)) {
    throw invalid(key, "must be an array of non-empty strings");
  }
  return v as string[];
}

/** Strict, padded standard base64 decoded to bytes. The caller owns the buffer and zeroes it. */
export function reqBase64(p: Params, key: string): Buffer {
  const v = reqString(p, key);
  if (v.length % 4 !== 0 || !BASE64_RE.test(v)) throw invalid(key, "must be base64");
  return Buffer.from(v, "base64");
}
