import { initVault, VaultExistsError } from "@agent-vault/core";
import { VERSION } from "../version.js";
import { invalid, paramsObject, reqString } from "./params.js";
import type { Registry } from "./types.js";

export const vaultMethods: Registry = {
  status: {
    mutates: false,
    returnsSecret: false,
    handler: (ctx, params) => {
      paramsObject(params, []);
      return { initialized: ctx.state.vault !== null, keystore: ctx.store.kind, version: VERSION };
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
};
