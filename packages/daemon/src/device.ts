import { createHash } from "node:crypto";
import os from "node:os";

export const HARNESSES = ["claude-code", "codex", "opencode", "cli", "mcp"] as const;
export type Harness = (typeof HARNESSES)[number];

/** Stable per-machine id for audit events; derived from the hostname, never the hostname itself. */
export const deviceId = `dev-${createHash("sha256").update(os.hostname()).digest("hex").slice(0, 12)}`;

/** A known harness name, or `cli`. */
export function asHarness(h: unknown): Harness {
  return (HARNESSES as readonly unknown[]).includes(h) ? (h as Harness) : "cli";
}

/** The `harness` of an RPC's params, or `cli` if it is absent or unknown. */
export function harnessOf(params: unknown): Harness {
  return asHarness(
    typeof params === "object" && params !== null && !Array.isArray(params)
      ? (params as Record<string, unknown>).harness
      : undefined,
  );
}
