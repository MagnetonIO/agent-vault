import { randomUUID } from "node:crypto";
import { mac, macEqual } from "@agent-vault/crypto";
import { inTransactionSync } from "./db.js";
import { AuditEventInvalidError, MetadataTamperError } from "./errors.js";
import { type Vault, vaultInternals } from "./vault.js";

export type AuditEvent = {
  ts: string;
  deviceId: string;
  harness?: "claude-code" | "codex" | "opencode" | "cli" | "mcp";
  actor: string;
  secretName?: string;
  bundle?: string;
  operation: string;
  outcome: "captured" | "brokered" | "blocked" | "error";
  requestId: string;
};

export type AuditInput = Omit<AuditEvent, "ts" | "requestId">;

type AuditRow = {
  seq: number;
  ts: string;
  event_json: string;
  prev_hmac: Uint8Array;
  hmac: Uint8Array;
};

const HARNESSES = ["claude-code", "codex", "opencode", "cli", "mcp"] as const;
const OUTCOMES = ["captured", "brokered", "blocked", "error"] as const;
/** The only keys an event may carry in the log, in the order they are serialized. */
const EVENT_KEYS = [
  "ts",
  "deviceId",
  "harness",
  "actor",
  "secretName",
  "bundle",
  "operation",
  "outcome",
  "requestId",
] as const;
/** Keys a caller may pass; `ts` and `requestId` are assigned here. */
const INPUT_KEYS: ReadonlySet<string> = new Set(
  EVENT_KEYS.filter((k) => k !== "ts" && k !== "requestId"),
);

const STRING_MAX = 200;
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1000;
const PAGE = 500;
const KIND = "audit entry";

const GENESIS = new Uint8Array(32);

function checkString(field: string, value: unknown): void {
  if (typeof value !== "string" || value.length === 0 || value.length > STRING_MAX) {
    throw new AuditEventInvalidError(
      field,
      `must be a non-empty string of at most ${STRING_MAX} characters`,
    );
  }
}

/** Reject anything that is not exactly an `AuditInput`. Errors name the field, never its value. */
function validate(e: unknown): asserts e is AuditInput {
  if (typeof e !== "object" || e === null || Array.isArray(e)) {
    throw new AuditEventInvalidError("(event)", "must be an object");
  }
  const rec = e as Record<string, unknown>;
  for (const key of Object.keys(rec)) {
    if (!INPUT_KEYS.has(key))
      throw new AuditEventInvalidError(key, "is not an allowed audit field");
  }
  for (const key of ["deviceId", "actor", "operation"]) checkString(key, rec[key]);
  for (const key of ["secretName", "bundle"]) {
    if (rec[key] !== undefined) checkString(key, rec[key]);
  }
  if (rec.harness !== undefined && !(HARNESSES as readonly unknown[]).includes(rec.harness)) {
    throw new AuditEventInvalidError("harness", "is not a known harness");
  }
  if (!(OUTCOMES as readonly unknown[]).includes(rec.outcome)) {
    throw new AuditEventInvalidError("outcome", "is not a known outcome");
  }
}

/** JSON with the fixed key order, so the bytes a row was MAC'd over are reproducible. */
function serialize(e: AuditEvent): string {
  const ordered: Record<string, unknown> = {};
  for (const key of EVENT_KEYS) {
    if (e[key] !== undefined) ordered[key] = e[key];
  }
  return JSON.stringify(ordered);
}

function rowMac(auditKey: Uint8Array, prev: Uint8Array, eventJson: string): Uint8Array {
  const body = new TextEncoder().encode(eventJson);
  const data = new Uint8Array(prev.length + body.length);
  data.set(prev, 0);
  data.set(body, prev.length);
  return mac(auditKey, data);
}

/** Column types are not enforced by SQLite; a row edited to hold the wrong type is tampered. */
function hasSaneTypes(row: AuditRow): boolean {
  return (
    row.prev_hmac instanceof Uint8Array &&
    row.hmac instanceof Uint8Array &&
    typeof row.event_json === "string"
  );
}

/**
 * Append an event to the hash chain: `hmac = HMAC(auditKey, prev_hmac || event_json)`, with 32 zero
 * bytes as the genesis `prev_hmac`. Unknown keys, bad enums and over-long strings throw
 * AuditEventInvalidError. `ts` and `requestId` are assigned here.
 */
export function appendAudit(v: Vault, input: AuditInput): AuditEvent {
  const { db, auditKey } = vaultInternals(v);
  validate(input);
  const event: AuditEvent = { ...input, ts: new Date().toISOString(), requestId: randomUUID() };
  const eventJson = serialize(event);
  inTransactionSync(db, () => {
    const last = db
      .prepare("SELECT hmac FROM audit_log ORDER BY seq DESC LIMIT 1")
      .get<{ hmac: Uint8Array }>();
    const prev = last?.hmac ?? GENESIS;
    db.prepare("INSERT INTO audit_log (ts, event_json, prev_hmac, hmac) VALUES (?, ?, ?, ?)").run(
      event.ts,
      eventJson,
      prev,
      rowMac(auditKey, prev, eventJson),
    );
  });
  return JSON.parse(eventJson) as AuditEvent;
}

/**
 * Walk the log from seq 1 and return the first expected seq whose row is missing, out of order,
 * unlinked from its predecessor, or whose hmac does not recompute.
 *
 * Limit: deleting the newest rows leaves a valid shorter chain, so tail truncation is undetectable
 * without an external anchor (the latest hmac stored somewhere an attacker cannot write). A later
 * append does show it: AUTOINCREMENT never reuses a seq, so the new row leaves a gap.
 */
export function verifyAudit(v: Vault): { ok: true } | { ok: false; brokenAtSeq: number } {
  const { db, auditKey } = vaultInternals(v);
  let expected = 1;
  let prev: Uint8Array = GENESIS;
  let after = 0;
  for (;;) {
    const rows = db
      .prepare("SELECT * FROM audit_log WHERE seq > ? ORDER BY seq LIMIT ?")
      .all<AuditRow>(after, PAGE);
    if (rows.length === 0) return { ok: true };
    for (const row of rows) {
      const good =
        hasSaneTypes(row) &&
        row.seq === expected &&
        macEqual(row.prev_hmac, prev) &&
        macEqual(rowMac(auditKey, row.prev_hmac, row.event_json), row.hmac);
      if (!good) return { ok: false, brokenAtSeq: expected };
      prev = row.hmac;
      expected++;
      after = row.seq;
    }
  }
}

/**
 * Events newest first, optionally for one secret and at or after `since` (ISO, inclusive). Filters
 * run on the signed `event_json`, not on the unsigned `ts` column. Each row scanned has its hmac
 * recomputed; a bad one throws MetadataTamperError. (Chain linkage is `verifyAudit`'s job.)
 */
export function queryAudit(
  v: Vault,
  f: { secretName?: string; since?: string; limit?: number },
): AuditEvent[] {
  const { db, auditKey } = vaultInternals(v);
  const limit = f.limit ?? DEFAULT_LIMIT;
  if (!Number.isInteger(limit) || limit < 1)
    throw new RangeError("limit must be a positive integer");
  const max = Math.min(limit, MAX_LIMIT);
  let since: string | undefined;
  if (f.since !== undefined) {
    const t = Date.parse(f.since);
    if (Number.isNaN(t)) throw new RangeError("since must be an ISO timestamp");
    since = new Date(t).toISOString();
  }
  const out: AuditEvent[] = [];
  let before = Number.MAX_SAFE_INTEGER;
  while (out.length < max) {
    const rows = db
      .prepare("SELECT * FROM audit_log WHERE seq < ? ORDER BY seq DESC LIMIT ?")
      .all<AuditRow>(before, PAGE);
    if (rows.length === 0) break;
    for (const row of rows) {
      before = row.seq;
      if (
        !hasSaneTypes(row) ||
        !macEqual(rowMac(auditKey, row.prev_hmac, row.event_json), row.hmac)
      ) {
        throw new MetadataTamperError(String(row.seq), KIND);
      }
      const e = JSON.parse(row.event_json) as AuditEvent;
      if (f.secretName !== undefined && e.secretName !== f.secretName) continue;
      if (since !== undefined && e.ts < since) continue;
      out.push(e);
      if (out.length >= max) break;
    }
  }
  return out;
}
