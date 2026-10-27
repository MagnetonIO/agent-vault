import { initVault, recoverVault, VaultExistsError } from "@agent-vault/core";
import { RpcError, VaultLockedError } from "../errors.js";
import { ERR } from "../rpc.js";
import { VERSION } from "../version.js";
import { invalid, paramsObject, reqString } from "./params.js";
import type { Registry } from "./types.js";

/** The recovery key is 32 bytes, which BIP39 writes as 24 words. */
const RECOVERY_WORDS = 24;

function reqWords(p: Record<string, unknown>): string[] {
  const words = p.words;
  if (
    !Array.isArray(words) ||
    words.length !== RECOVERY_WORDS ||
    words.some((w) => typeof w !== "string" || w.length === 0 || w.length > 32)
  ) {
    throw invalid("words", `must be an array of ${RECOVERY_WORDS} words`);
  }
  return words as string[];
}

export const vaultMethods: Registry = {
  status: {
    mutates: false,
    returnsSecret: false,
    handler: (ctx, params) => {
      paramsObject(params, []);
      return {
        initialized: ctx.state.vault !== null,
        locked: ctx.state.locked,
        keystore: ctx.store.kind,
        version: VERSION,
        pid: process.pid,
      };
    },
  },
  "vault.init": {
    mutates: true,
    returnsSecret: false,
    // The recovery words cross the wire here, once, by design. They are shown to the user and
    // stored nowhere, so this is not a secret-returning read.
    handler: async (ctx, params) => {
      const p = paramsObject(params, ["keystore", "harness"]);
      if (reqString(p, "keystore") !== ctx.store.kind) {
        throw invalid("keystore", "does not match the daemon's key store");
      }
      if (ctx.state.locked) throw new VaultLockedError();
      if (ctx.state.vault || ctx.state.initializing) throw new VaultExistsError();
      ctx.state.initializing = true;
      try {
        const { vault, recoveryWords } = await initVault({ paths: ctx.paths, store: ctx.store });
        if (ctx.state.closed) {
          vault.close();
        } else {
          ctx.state.vault = vault;
        }
        return { recoveryWords };
      } finally {
        ctx.state.initializing = false;
      }
    },
  },
  "vault.recover": {
    mutates: true,
    returnsSecret: false,
    // Takes the recovery words (never returned, never logged), makes a fresh device root key in
    // the daemon's store and opens the vault with it. Works on a locked daemon, where the root
    // key is gone, and on an open one, which is reopened.
    handler: async (ctx, params) => {
      const words = reqWords(paramsObject(params, ["words", "harness"]));
      if (ctx.state.initializing) {
        throw new RpcError(ERR.APP, "another vault operation is in progress");
      }
      ctx.state.initializing = true;
      try {
        const vault = await recoverVault({ paths: ctx.paths, store: ctx.store, words });
        if (ctx.state.closed) {
          vault.close();
        } else {
          const previous = ctx.state.vault;
          ctx.state.vault = vault;
          ctx.state.locked = false;
          previous?.close();
        }
        return { ok: true };
      } finally {
        ctx.state.initializing = false;
      }
    },
  },
};
