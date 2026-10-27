import { createHash } from "node:crypto";
import { parseRef } from "@agent-vault/core";

export const NAME_MAX = 128;

/** One path segment of a secret name: lower case, `[a-z0-9._-]`, starting with an alphanumeric. */
export function sanitizeSegment(raw: string): string {
  const s = raw
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[^a-z0-9]+/, "")
    .replace(/-{2,}/g, "-");
  return s === "" ? "x" : s;
}

/** True if `name` is a legal secret or bundle name. */
export const isLegalName = (name: string): boolean => parseRef(`vault://${name}`) !== null;

/** A legal secret name made from `/`-separated parts. */
export function sanitizeName(name: string): string {
  const parts = name.split("/").map(sanitizeSegment);
  let out = parts.join("/");
  if (out.length > NAME_MAX) out = out.slice(0, NAME_MAX).replace(/[/.\-_]+$/, "");
  return isLegalName(out) ? out : "secret/unnamed";
}

export const lowerDashes = (env: string): string => env.toLowerCase().replace(/_/g, "-");

/** `mcp-<server>`; past 128 characters it is cut and ends in `-<sha256 8 hex>` of the server. */
export function bundleBase(server: string): string {
  const name = `mcp-${sanitizeSegment(server).replace(/\//g, "-")}`;
  if (name.length <= NAME_MAX) return name;
  const hash = createHash("sha256").update(server, "utf8").digest("hex").slice(0, 8);
  return `${name.slice(0, NAME_MAX - hash.length - 1)}-${hash}`;
}

/** `base-2`, `base-3`, …: the n-th candidate after `base`, kept within the length limit. */
export const suffixed = (base: string, n: number): string =>
  `${base.slice(0, NAME_MAX - `-${n}`.length)}-${n}`;
