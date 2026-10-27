import { describe, expect, test } from "vitest";
import {
  type AuditEvent,
  AuditEventInvalidError,
  appendAudit,
  MetadataTamperError,
  queryAudit,
  VaultClosedError,
  verifyAudit,
} from "../src/index.js";
import { useVaultEnv } from "./helpers.js";

const env = useVaultEnv();

const base = {
  deviceId: "dev-1",
  actor: "claude-code",
  operation: "run",
  outcome: "brokered",
} as const;

type Raw = { seq: number; ts: string; event_json: string; prev_hmac: Uint8Array; hmac: Uint8Array };

describe("appendAudit", () => {
  test("fills ts and requestId and returns the stored event", async () => {
    const v = await env.newVault();
    const before = Date.now();
    const e = appendAudit(v, { ...base, harness: "cli", secretName: "github/token", bundle: "b" });
    expect(e).toMatchObject({ ...base, harness: "cli", secretName: "github/token", bundle: "b" });
    expect(e.requestId).toMatch(/^[0-9a-f-]{36}$/);
    expect(new Date(e.ts).toISOString()).toBe(e.ts);
    expect(Date.parse(e.ts)).toBeGreaterThanOrEqual(before);
    expect(queryAudit(v, {})).toEqual([e]);
  });

  test("event_json has a fixed key order and omits undefined keys", async () => {
    const v = await env.newVault();
    // Keys supplied in a scrambled order, with an undefined one.
    appendAudit(v, {
      outcome: "captured",
      operation: "capture",
      bundle: undefined,
      secretName: "a",
      actor: "cli",
      harness: "mcp",
      deviceId: "d",
    } as never);
    const row = env.withRawDb((db) => db.prepare("SELECT * FROM audit_log").get<Raw>());
    expect(Object.keys(JSON.parse(row?.event_json ?? "{}"))).toEqual([
      "ts",
      "deviceId",
      "harness",
      "actor",
      "secretName",
      "operation",
      "outcome",
      "requestId",
    ]);
  });

  test("the genesis row chains from 32 zero bytes, then each row from the last hmac", async () => {
    const v = await env.newVault();
    appendAudit(v, base);
    appendAudit(v, base);
    const rows = env.withRawDb((db) =>
      db.prepare("SELECT * FROM audit_log ORDER BY seq").all<Raw>(),
    );
    expect(rows.map((r) => r.seq)).toEqual([1, 2]);
    expect(Array.from(rows[0]?.prev_hmac ?? [])).toEqual(new Array(32).fill(0));
    expect(rows[1]?.prev_hmac).toEqual(rows[0]?.hmac);
    expect(rows[0]?.hmac).not.toEqual(rows[1]?.hmac);
  });

  test("rejects unknown keys without echoing the value", async () => {
    const v = await env.newVault();
    const secret = "sk_live_SUPERSECRETVALUE";
    let err: unknown;
    try {
      appendAudit(v, { ...base, value: secret } as never);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(AuditEventInvalidError);
    expect((err as Error).message).toContain("value");
    expect((err as Error).message).not.toContain(secret);
    expect(queryAudit(v, {})).toEqual([]);
  });

  test("caller cannot set ts or requestId", async () => {
    const v = await env.newVault();
    expect(() => appendAudit(v, { ...base, ts: "2020-01-01T00:00:00.000Z" } as never)).toThrow(
      AuditEventInvalidError,
    );
    expect(() => appendAudit(v, { ...base, requestId: "r" } as never)).toThrow(
      AuditEventInvalidError,
    );
  });

  test("validates harness and outcome enums, without echoing the bad value", async () => {
    const v = await env.newVault();
    let err: unknown;
    try {
      appendAudit(v, { ...base, harness: "sk_live_LEAK" } as never);
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(AuditEventInvalidError);
    expect((err as Error).message).toContain("harness");
    expect((err as Error).message).not.toContain("sk_live_LEAK");
    expect(() => appendAudit(v, { ...base, outcome: "ok" } as never)).toThrow(
      AuditEventInvalidError,
    );
    for (const harness of ["claude-code", "codex", "opencode", "cli", "mcp"] as const) {
      appendAudit(v, { ...base, harness });
    }
    for (const outcome of ["captured", "brokered", "blocked", "error"] as const) {
      appendAudit(v, { ...base, outcome });
    }
  });

  test("operation and actor must be non-empty strings of at most 200 chars", async () => {
    const v = await env.newVault();
    for (const key of ["operation", "actor"] as const) {
      for (const bad of ["", "x".repeat(201), 5, null, undefined]) {
        expect(() => appendAudit(v, { ...base, [key]: bad } as never)).toThrow(
          AuditEventInvalidError,
        );
      }
      appendAudit(v, { ...base, [key]: "x".repeat(200) });
    }
  });

  test("optional string fields are type-checked when present", async () => {
    const v = await env.newVault();
    expect(() => appendAudit(v, { ...base, secretName: 5 } as never)).toThrow(
      AuditEventInvalidError,
    );
    expect(() => appendAudit(v, { ...base, bundle: "" } as never)).toThrow(AuditEventInvalidError);
    expect(() => appendAudit(v, null as never)).toThrow(AuditEventInvalidError);
  });

  test("a closed vault throws VaultClosedError", async () => {
    const v = await env.newVault();
    v.close();
    expect(() => appendAudit(v, base)).toThrow(VaultClosedError);
    expect(() => verifyAudit(v)).toThrow(VaultClosedError);
    expect(() => queryAudit(v, {})).toThrow(VaultClosedError);
  });
});

describe("verifyAudit", () => {
  async function three() {
    const v = await env.newVault();
    for (const n of ["a", "b", "c"]) appendAudit(v, { ...base, secretName: n });
    return v;
  }

  test("an empty log is ok", async () => {
    const v = await env.newVault();
    expect(verifyAudit(v)).toEqual({ ok: true });
  });

  test("3 appends verify", async () => {
    expect(verifyAudit(await three())).toEqual({ ok: true });
  });

  test("deleting the middle row breaks at seq 2", async () => {
    const v = await three();
    env.withRawDb((db) => db.exec("DELETE FROM audit_log WHERE seq = 2"));
    expect(verifyAudit(v)).toEqual({ ok: false, brokenAtSeq: 2 });
  });

  test("deleting the first row breaks at seq 1", async () => {
    const v = await three();
    env.withRawDb((db) => db.exec("DELETE FROM audit_log WHERE seq = 1"));
    expect(verifyAudit(v)).toEqual({ ok: false, brokenAtSeq: 1 });
  });

  test("editing event_json breaks at that row", async () => {
    const v = await three();
    env.withRawDb((db) =>
      db
        .prepare(
          "UPDATE audit_log SET event_json = REPLACE(event_json, '\"b\"', '\"zzz\"') WHERE seq = 2",
        )
        .run(),
    );
    expect(verifyAudit(v)).toEqual({ ok: false, brokenAtSeq: 2 });
  });

  test("swapping two rows' hmac breaks at the first of them", async () => {
    const v = await three();
    env.withRawDb((db) => {
      const [a, b] = db
        .prepare("SELECT hmac FROM audit_log WHERE seq IN (1, 2) ORDER BY seq")
        .all<{ hmac: Uint8Array }>();
      db.prepare("UPDATE audit_log SET hmac = ? WHERE seq = 1").run(b?.hmac as Uint8Array);
      db.prepare("UPDATE audit_log SET hmac = ? WHERE seq = 2").run(a?.hmac as Uint8Array);
    });
    expect(verifyAudit(v)).toEqual({ ok: false, brokenAtSeq: 1 });
  });

  test("rewriting prev_hmac to bridge a deleted row still fails", async () => {
    const v = await three();
    env.withRawDb((db) => {
      const first = db
        .prepare("SELECT hmac FROM audit_log WHERE seq = 1")
        .get<{ hmac: Uint8Array }>();
      db.exec("DELETE FROM audit_log WHERE seq = 2");
      db.prepare("UPDATE audit_log SET prev_hmac = ? WHERE seq = 3").run(first?.hmac as Uint8Array);
    });
    expect(verifyAudit(v)).toEqual({ ok: false, brokenAtSeq: 2 });
  });

  test("a forged row without the audit key fails", async () => {
    const v = await three();
    env.withRawDb((db) => {
      const last = db
        .prepare("SELECT hmac FROM audit_log WHERE seq = 3")
        .get<{ hmac: Uint8Array }>();
      db.prepare(
        "INSERT INTO audit_log (ts, event_json, prev_hmac, hmac) VALUES ('t', '{}', ?, ?)",
      ).run(last?.hmac as Uint8Array, new Uint8Array(32));
    });
    expect(verifyAudit(v)).toEqual({ ok: false, brokenAtSeq: 4 });
  });

  test("truncating the newest rows and appending again leaves a seq gap", async () => {
    // Tail truncation alone is undetectable without an external anchor (see audit.ts); AUTOINCREMENT
    // means a later append does not reuse the freed seq, so the gap shows up.
    const v = await three();
    env.withRawDb((db) => db.exec("DELETE FROM audit_log WHERE seq = 3"));
    expect(verifyAudit(v)).toEqual({ ok: true });
    appendAudit(v, base);
    expect(verifyAudit(v)).toEqual({ ok: false, brokenAtSeq: 3 });
  });

  test("the chain survives close and reopen", async () => {
    const v = await three();
    v.close();
    const { openVault } = await import("../src/index.js");
    const again = await openVault({ paths: env.paths, store: env.store });
    try {
      appendAudit(again, base);
      expect(verifyAudit(again)).toEqual({ ok: true });
    } finally {
      again.close();
    }
  });
});

describe("queryAudit", () => {
  test("newest first, default limit 100", async () => {
    const v = await env.newVault();
    for (let i = 0; i < 105; i++) appendAudit(v, { ...base, operation: `op${i}` });
    const out = queryAudit(v, {});
    expect(out).toHaveLength(100);
    expect(out[0]?.operation).toBe("op104");
    expect(out[99]?.operation).toBe("op5");
  });

  test("limit is honoured and capped at 1000", async () => {
    const v = await env.newVault();
    for (let i = 0; i < 5; i++) appendAudit(v, base);
    expect(queryAudit(v, { limit: 2 })).toHaveLength(2);
    expect(queryAudit(v, { limit: 5000 })).toHaveLength(5);
    expect(() => queryAudit(v, { limit: 0 })).toThrow(RangeError);
    expect(() => queryAudit(v, { limit: 1.5 })).toThrow(RangeError);
  });

  test("filters by secretName", async () => {
    const v = await env.newVault();
    appendAudit(v, { ...base, secretName: "a", operation: "1" });
    appendAudit(v, { ...base, secretName: "b", operation: "2" });
    appendAudit(v, { ...base, operation: "3" });
    appendAudit(v, { ...base, secretName: "a", operation: "4" });
    expect(queryAudit(v, { secretName: "a" }).map((e) => e.operation)).toEqual(["4", "1"]);
    expect(queryAudit(v, { secretName: "none" })).toEqual([]);
  });

  test("since is inclusive", async () => {
    const v = await env.newVault();
    const e1 = appendAudit(v, { ...base, operation: "1" });
    await new Promise((r) => setTimeout(r, 5));
    const e2 = appendAudit(v, { ...base, operation: "2" });
    expect(queryAudit(v, { since: e2.ts }).map((e) => e.operation)).toEqual(["2"]);
    expect(queryAudit(v, { since: e1.ts }).map((e) => e.operation)).toEqual(["2", "1"]);
    expect(queryAudit(v, { since: "2999-01-01T00:00:00Z" })).toEqual([]);
    expect(() => queryAudit(v, { since: "not a date" })).toThrow(RangeError);
  });

  test("since is judged on the signed event, not the ts column", async () => {
    const v = await env.newVault();
    appendAudit(v, { ...base, operation: "1" });
    env.withRawDb((db) => db.exec("UPDATE audit_log SET ts = '1999-01-01T00:00:00.000Z'"));
    // The ts column was rewritten; the event_json is untouched, so the row is still found.
    expect(queryAudit(v, { since: "2000-01-01T00:00:00Z" })).toHaveLength(1);
  });

  test("a tampered row throws MetadataTamperError", async () => {
    const v = await env.newVault();
    appendAudit(v, { ...base, secretName: "a" });
    appendAudit(v, { ...base, secretName: "b" });
    env.withRawDb((db) =>
      db
        .prepare(
          "UPDATE audit_log SET event_json = REPLACE(event_json, '\"a\"', '\"x\"') WHERE seq = 1",
        )
        .run(),
    );
    expect(() => queryAudit(v, {})).toThrow(MetadataTamperError);
    // Filtering for another secret must still verify the rows it skips.
    expect(() => queryAudit(v, { secretName: "b" })).toThrow(MetadataTamperError);
  });

  test("returned events carry exactly the allowlisted keys", async () => {
    const v = await env.newVault();
    const e = appendAudit(v, { ...base, harness: "codex" });
    const [got] = queryAudit(v, {}) as AuditEvent[];
    expect(got).toEqual(e);
    expect(Object.keys(got as object).sort()).toEqual(
      ["actor", "deviceId", "harness", "operation", "outcome", "requestId", "ts"].sort(),
    );
  });
});
