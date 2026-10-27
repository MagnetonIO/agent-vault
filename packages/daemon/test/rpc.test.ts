import { type AuditEvent, openDb, type SecretMeta } from "@agent-vault/core";
import { describe, expect, test } from "vitest";
import { RpcError } from "../src/errors.js";
import type { Registry } from "../src/methods/index.js";
import { registry } from "../src/methods/index.js";
import { b64, MODES, RawPeer, useDaemon } from "./helpers.js";

const SECRET = "s3cr3t-value-for-tests-0042";

/** Reject with the RpcError so a test can inspect code and data. */
async function rpcError(p: Promise<unknown>): Promise<RpcError> {
  try {
    await p;
  } catch (err) {
    if (err instanceof RpcError) return err;
    throw err;
  }
  throw new Error("expected an RpcError");
}

const testMethods: Registry = {
  ...registry,
  "test.notify": {
    mutates: false,
    returnsSecret: false,
    handler: (ctx) => {
      ctx.notify("test.event", { n: 1 });
      ctx.notify("test.event", { n: 2 });
      return "done";
    },
  },
  "test.hang": { mutates: false, returnsSecret: false, handler: () => new Promise(() => {}) },
  "test.unserializable": { mutates: false, returnsSecret: false, handler: () => 10n },
  "test.boom": {
    mutates: false,
    returnsSecret: false,
    handler: () => {
      throw new TypeError("details that must not reach the wire");
    },
  },
};

describe.each(MODES)("daemon over %s", (mode) => {
  describe("uninitialized", () => {
    const env = useDaemon(mode);

    test("status works and reports the key store", async () => {
      expect(await env.client.call("status")).toEqual({
        initialized: false,
        locked: false,
        keystore: "memory",
        version: "0.0.0",
        pid: process.pid,
      });
    });

    test("every other method is VaultNotInitializedError", async () => {
      for (const method of ["secret.list", "secret.put", "bundle.list", "audit.verify"]) {
        const err = await rpcError(env.client.call(method, {}));
        expect(err.code).toBe(-32000);
        expect(err.data).toEqual({ name: "VaultNotInitializedError" });
      }
    });

    test("vault.init needs the matching key store", async () => {
      const err = await rpcError(env.client.call("vault.init", { keystore: "keyfile" }));
      expect(err.code).toBe(-32602);
      expect((await env.client.call<{ initialized: boolean }>("status")).initialized).toBe(false);
    });

    test("vault.init returns the 24 recovery words once, then the vault is usable", async () => {
      const { recoveryWords } = await env.client.call<{ recoveryWords: string[] }>("vault.init", {
        keystore: "memory",
      });
      expect(recoveryWords).toHaveLength(24);
      expect((await env.client.call<{ initialized: boolean }>("status")).initialized).toBe(true);
      expect(await env.client.call("secret.list")).toEqual([]);

      const again = await rpcError(env.client.call("vault.init", { keystore: "memory" }));
      expect(again.data).toEqual({ name: "VaultExistsError" });

      // The words are not in the audit log, but the init is.
      const events = await env.client.call<AuditEvent[]>("audit.query");
      expect(JSON.stringify(events)).not.toContain(recoveryWords.join(" "));
      expect(events.map((e) => [e.operation, e.outcome])).toEqual([
        ["vault.init", "error"],
        ["vault.init", "brokered"],
      ]);
    });
  });

  describe("secrets", () => {
    const env = useDaemon(mode, { init: true });

    test("secret.put then secret.list: one entry, no value anywhere", async () => {
      const meta = await env.client.call<SecretMeta>("secret.put", {
        name: "app/token",
        valueB64: b64(SECRET),
        type: "api-key",
        tags: ["ci"],
      });
      expect(meta).toMatchObject({ name: "app/token", type: "api-key", length: SECRET.length });
      const list = await env.client.call<SecretMeta[]>("secret.list");
      expect(list).toHaveLength(1);
      expect(Object.keys(list[0] as SecretMeta).sort()).toEqual([
        "createdAt",
        "length",
        "name",
        "tags",
        "type",
        "updatedAt",
      ]);
      expect(JSON.stringify([meta, list])).not.toMatch(/value|ciphertext|s3cr3t/i);
    });

    test("a missing name is detected from the value", async () => {
      const token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
      const meta = await env.client.call<SecretMeta>("secret.put", { valueB64: b64(token) });
      expect(meta.name).toMatch(/^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*)*-\d{8}$/);
      expect(meta.type).not.toBe("generic");
      // A second one of the same kind gets the taken-suffix.
      const second = await env.client.call<SecretMeta>("secret.put", {
        valueB64: b64(token.replace("a", "b")),
      });
      expect(second.name).toBe(`${meta.name}-2`);
    });

    test("an undetectable value is named secret/unnamed-<date> with the same suffix rule", async () => {
      const stamp = new Date().toISOString().slice(0, 10).replaceAll("-", "");
      const first = await env.client.call<SecretMeta>("secret.put", { valueB64: b64("plain one") });
      const second = await env.client.call<SecretMeta>("secret.put", {
        valueB64: b64("plain two"),
      });
      expect(first).toMatchObject({ name: `secret/unnamed-${stamp}`, type: "generic" });
      expect(second.name).toBe(`secret/unnamed-${stamp}-2`);
    });

    test("secret.remove", async () => {
      await env.client.call("secret.put", { name: "gone/soon", valueB64: b64(SECRET) });
      expect(await env.client.call("secret.remove", { name: "gone/soon" })).toEqual({
        removed: true,
      });
      expect(await env.client.call("secret.remove", { name: "gone/soon" })).toEqual({
        removed: false,
      });
    });

    test.each([
      ["no value", { name: "a/b" }],
      ["a plaintext value field", { name: "a/b", value: SECRET }],
      ["bad base64", { name: "a/b", valueB64: "not base64!" }],
      ["a bad name", { name: "Bad Name", valueB64: b64("x") }],
      ["tags of the wrong type", { name: "a/b", valueB64: b64("x"), tags: [1] }],
    ])("secret.put with %s is -32602 and never echoes the value", async (_, params) => {
      const err = await rpcError(env.client.call("secret.put", params));
      expect(err.code).toBe(-32602);
      expect(JSON.stringify(err)).not.toContain(SECRET);
      expect(err.message).not.toContain("Bad Name");
    });
  });

  describe("bundles and audit", () => {
    const env = useDaemon(mode, { init: true });

    test("create, grant, allowExe, list", async () => {
      await env.client.call("secret.put", { name: "gh/token", valueB64: b64(SECRET) });
      await env.client.call("bundle.create", { name: "deploy" });
      await env.client.call("bundle.grant", {
        bundle: "deploy",
        env: "GITHUB_TOKEN",
        secret: "gh/token",
      });
      const exe = process.execPath;
      await env.client.call("bundle.allowExe", { bundle: "deploy", path: exe });
      expect(await env.client.call("bundle.list")).toEqual([
        { name: "deploy", env: { GITHUB_TOKEN: "gh/token" }, exes: [exe] },
      ]);
    });

    test("every mutating method writes one audit event", async () => {
      const c = env.client;
      await c.call("secret.put", { name: "gh/token", valueB64: b64(SECRET), harness: "codex" });
      await c.call("bundle.create", { name: "deploy" });
      await c.call("bundle.grant", { bundle: "deploy", env: "T", secret: "gh/token" });
      await c.call("bundle.allowExe", { bundle: "deploy", path: process.execPath });
      await c.call("secret.remove", { name: "gh/token", harness: "bogus" });

      const events = (await c.call<AuditEvent[]>("audit.query")).reverse();
      expect(events.map((e) => [e.operation, e.outcome, e.harness])).toEqual([
        ["vault.init", "brokered", "cli"],
        ["secret.put", "captured", "codex"],
        ["bundle.create", "brokered", "cli"],
        ["bundle.grant", "brokered", "cli"],
        ["bundle.allowExe", "brokered", "cli"],
        ["secret.remove", "brokered", "cli"],
      ]);
      expect(events[1]).toMatchObject({ secretName: "gh/token", actor: "rpc" });
      expect(events[3]).toMatchObject({ bundle: "deploy", secretName: "gh/token" });
      expect(events[2]?.deviceId).toMatch(/^dev-[0-9a-f]{12}$/);
      expect(JSON.stringify(events)).not.toContain(SECRET);
      expect(await c.call("audit.verify")).toEqual({ ok: true });

      const forSecret = await c.call<AuditEvent[]>("audit.query", { secretName: "gh/token" });
      expect(forSecret.map((e) => e.operation).sort()).toEqual([
        "bundle.grant",
        "secret.put",
        "secret.remove",
      ]);
    });

    test("reads do not write audit events", async () => {
      await env.client.call("secret.list");
      await env.client.call("bundle.list");
      await env.client.call("audit.verify");
      expect(await env.client.call<AuditEvent[]>("audit.query")).toHaveLength(1);
    });

    test("a failed mutation is audited as an error, then the error is rethrown", async () => {
      const err = await rpcError(
        env.client.call("bundle.grant", { bundle: "nope", env: "T", secret: "missing/one" }),
      );
      expect(err.code).toBe(-32000);
      expect(err.data).toEqual({ name: "SecretNotFoundError" });
      const [last] = await env.client.call<AuditEvent[]>("audit.query", { limit: 1 });
      expect(last).toMatchObject({
        operation: "bundle.grant",
        outcome: "error",
        bundle: "nope",
        secretName: "missing/one",
      });
    });

    test("a failed secret.put is audited as an error", async () => {
      await env.client.call("secret.put", { name: "tamper/me", valueB64: b64(SECRET) });
      const db = openDb(env.paths.dbFile);
      try {
        db.prepare("UPDATE secrets SET type = 'evil' WHERE name = 'tamper/me'").run();
      } finally {
        db.close();
      }
      const err = await rpcError(
        env.client.call("secret.put", { name: "tamper/me", valueB64: b64("another") }),
      );
      expect(err.data).toEqual({ name: "MetadataTamperError" });
      const [last] = await env.client.call<AuditEvent[]>("audit.query", { limit: 1 });
      expect(last).toMatchObject({
        operation: "secret.put",
        outcome: "error",
        secretName: "tamper/me",
      });
    });

    test("audit.query rejects bad params", async () => {
      expect((await rpcError(env.client.call("audit.query", { limit: 0 }))).code).toBe(-32602);
      expect((await rpcError(env.client.call("audit.query", { since: "nope" }))).code).toBe(-32602);
    });
  });

  describe("protocol", () => {
    const env = useDaemon(mode, { init: true, methods: testMethods });

    test("an unknown method is -32601, including inherited property names", async () => {
      for (const method of ["no.such", "constructor", "__proto__", "toString"]) {
        const err = await rpcError(env.client.call(method));
        expect(err.code).toBe(-32601);
      }
    });

    test("raw lines: parse error, invalid requests, notifications, pipelining", async () => {
      const peer = await RawPeer.open(env.endpoint);
      try {
        peer.send("{not json\n");
        expect(JSON.parse((await peer.line()) as string)).toMatchObject({
          id: null,
          error: { code: -32700 },
        });

        peer.send("[]\n");
        expect(JSON.parse((await peer.line()) as string)).toMatchObject({
          id: null,
          error: { code: -32600 },
        });

        peer.send('{"id":7,"method":"status"}\n');
        expect(JSON.parse((await peer.line()) as string)).toMatchObject({
          id: 7,
          error: { code: -32600 },
        });

        peer.send('{"jsonrpc":"2.0","id":8,"method":"status","params":"x"}\n');
        expect(JSON.parse((await peer.line()) as string)).toMatchObject({
          id: 8,
          error: { code: -32600 },
        });

        peer.send('{"jsonrpc":"2.0","id":9,"method":"status","params":[1]}\n');
        expect(JSON.parse((await peer.line()) as string)).toMatchObject({
          id: 9,
          error: { code: -32602 },
        });

        // A notification gets no reply, even for an unknown method; the next line is the answer
        // to the request after it. Two requests in one write are both answered.
        peer.send(
          [
            '{"jsonrpc":"2.0","method":"no.such"}',
            '{"jsonrpc":"2.0","id":"a","method":"status"}',
            '{"jsonrpc":"2.0","id":"b","method":"secret.list"}',
            "",
          ].join("\n"),
        );
        const replies = [await peer.line(), await peer.line()].map(
          (l) => JSON.parse(l as string) as { id: string },
        );
        expect(replies.map((r) => r.id).sort()).toEqual(["a", "b"]);
        expect(await peer.line(150)).toBeNull();
      } finally {
        peer.destroy();
      }
    });

    test("app errors carry the class name and message; others are opaque", async () => {
      const app = await rpcError(
        env.client
          .call("bundle.create", { name: "dup" })
          .then(() => env.client.call("bundle.create", { name: "dup" })),
      );
      expect(app).toMatchObject({
        code: -32000,
        message: 'bundle already exists: "dup"',
        data: { name: "BundleExistsError" },
      });

      const boom = await rpcError(env.client.call("test.boom"));
      expect(boom.code).toBe(-32603);
      expect(boom.message).toBe("internal error");
      expect(boom.data).toEqual({ name: "TypeError" });
      expect(JSON.stringify(boom)).not.toContain("details that must not");
    });

    test("a result that cannot be serialized is -32603 and the connection survives", async () => {
      const err = await rpcError(env.client.call("test.unserializable"));
      expect(err).toMatchObject({ code: -32603, message: "internal error" });
      expect(await env.client.call("status")).toBeTruthy();
    });

    test("server notifications reach onNotification before the result", async () => {
      const seen: [string, unknown][] = [];
      env.client.onNotification((method, params) => seen.push([method, params]));
      expect(await env.client.call("test.notify")).toBe("done");
      expect(seen).toEqual([
        ["test.event", { n: 1 }],
        ["test.event", { n: 2 }],
      ]);
    });

    test("a request that gets no answer times out; closing fails the rest", async () => {
      const { connect } = await import("../src/client.js");
      const quick = await connect(env.endpoint, { requestTimeoutMs: 150 });
      await expect(quick.call("test.hang")).rejects.toThrow(/timed out/);
      const hanging = quick.call("test.hang");
      quick.close();
      await expect(hanging).rejects.toThrow(/closed/);
      await expect(quick.call("status")).rejects.toThrow(/closed/);
    });

    test("status reports the package version", async () => {
      const { version } = await import("../package.json", { with: { type: "json" } }).then(
        (m) => m.default,
      );
      expect((await env.client.call<{ version: string }>("status")).version).toBe(version);
    });
  });
});
