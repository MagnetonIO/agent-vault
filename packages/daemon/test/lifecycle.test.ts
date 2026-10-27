import { openVault, queryAudit } from "@agent-vault/core";
import { describe, expect, test } from "vitest";
import { connect } from "../src/client.js";
import type { RpcError } from "../src/errors.js";
import { startDaemon } from "../src/server.js";
import { b64, MODES, useDaemon } from "./helpers.js";

const VALUE = "lifecycle-secret-value-9931";

async function rpcError(p: Promise<unknown>): Promise<RpcError> {
  try {
    await p;
  } catch (err) {
    return err as RpcError;
  }
  throw new Error("expected an RpcError");
}

describe.each(MODES)("daemon lifecycle over %s", (mode) => {
  describe("daemon.stop", () => {
    const env = useDaemon(mode);

    test("replies, closes the daemon and frees the endpoint", async () => {
      expect(await env.client.call("daemon.stop")).toEqual({ stopping: true });
      await env.daemon.closed;
      await expect(connect(env.endpoint, { timeoutMs: 300 })).rejects.toThrow();
    });

    test("is audited once the vault is open", async () => {
      await env.client.call("vault.init", { keystore: "memory" });
      expect(await env.client.call("daemon.stop")).toEqual({ stopping: true });
      await env.daemon.closed;
      const vault = await openVault({ paths: env.paths, store: env.store });
      try {
        const events = queryAudit(vault, {}).filter((e) => e.operation === "daemon.stop");
        expect(events).toMatchObject([{ outcome: "brokered", actor: "rpc" }]);
      } finally {
        vault.close();
      }
    });

    test("takes no params", async () => {
      const err = await rpcError(env.client.call("daemon.stop", { now: true }));
      expect(err.code).toBe(-32602);
      expect(await env.client.call("status")).toMatchObject({ initialized: false });
    });
  });

  describe("vault.recover", () => {
    const env = useDaemon(mode);

    /** Init, store a secret, then lose the device root key and restart the daemon. */
    async function lostKey(): Promise<{
      words: string[];
      restarted: Awaited<ReturnType<typeof startDaemon>>;
    }> {
      const { recoveryWords } = await env.client.call<{ recoveryWords: string[] }>("vault.init", {
        keystore: "memory",
      });
      await env.client.call("secret.put", { name: "kept/secret", valueB64: b64(VALUE) });
      await env.daemon.close();
      await env.store.remove();
      const restarted = await startDaemon({
        paths: env.paths,
        store: env.store,
        endpoint: env.endpoint,
      });
      return { words: recoveryWords, restarted };
    }

    test("a daemon whose root key is gone starts locked, then recovers from the words", async () => {
      const { words, restarted } = await lostKey();
      const client = await connect(env.endpoint);
      try {
        expect(await client.call("status")).toMatchObject({ initialized: false, locked: true });
        const locked = await rpcError(client.call("secret.list"));
        expect(locked.message).toBe("vault is locked; run: agent-vault recover");
        expect(locked.data).toEqual({ name: "VaultLockedError" });
        // init must not pave over a vault this device merely cannot open.
        const init = await rpcError(client.call("vault.init", { keystore: "memory" }));
        expect(init.message).toBe("vault is locked; run: agent-vault recover");

        expect(await client.call("vault.recover", { words })).toEqual({ ok: true });
        expect(await client.call("status")).toMatchObject({ initialized: true, locked: false });
        expect(await client.call("secret.list")).toMatchObject([
          { name: "kept/secret", length: VALUE.length },
        ]);
        expect(await env.store.load()).not.toBeNull();
      } finally {
        client.close();
        await restarted.close();
      }
    });

    test("wrong words are refused and leave the daemon locked", async () => {
      const { words, restarted } = await lostKey();
      const client = await connect(env.endpoint);
      try {
        const wrong = [...words].reverse();
        const err = await rpcError(client.call("vault.recover", { words: wrong }));
        expect(err.message).toBe("recovery words are not valid for this vault");
        expect(await client.call("status")).toMatchObject({ initialized: false, locked: true });
      } finally {
        client.close();
        await restarted.close();
      }
    });

    test("malformed params are invalid params", async () => {
      await env.client.call("vault.init", { keystore: "memory" });
      for (const params of [
        undefined,
        {},
        { words: "a b c" },
        { words: ["a", "b"] },
        { words: [1] },
      ]) {
        expect((await rpcError(env.client.call("vault.recover", params))).code).toBe(-32602);
      }
    });

    test("an open vault is reopened with a fresh root key and is audited", async () => {
      const { recoveryWords } = await env.client.call<{ recoveryWords: string[] }>("vault.init", {
        keystore: "memory",
      });
      await env.client.call("secret.put", { name: "kept/secret", valueB64: b64(VALUE) });
      const before = await env.store.load();
      const recovered = await env.client.call("vault.recover", { words: recoveryWords });
      expect(recovered).toEqual({ ok: true });
      expect(await env.store.load()).not.toEqual(before);
      expect(await env.client.call("secret.list")).toMatchObject([{ name: "kept/secret" }]);
      const audit = await env.client.call("audit.query", {});
      expect((audit as unknown[]).slice(0, 2)).toMatchObject([
        { operation: "vault.recover", outcome: "brokered" },
        { operation: "secret.put" },
      ]);
      // The words go in once and come back nowhere.
      const wire = JSON.stringify([recovered, audit, await env.client.call("status")]);
      // Single BIP39 words collide with ordinary JSON ("memory", "version"); check word runs instead.
      expect(wire).not.toContain(recoveryWords.join(" "));
      for (let i = 0; i + 3 <= recoveryWords.length; i++) {
        expect(wire).not.toContain(recoveryWords.slice(i, i + 3).join(" "));
      }
    });
  });
});
