import { auditMethods } from "./audit.js";
import { bundleMethods } from "./bundle.js";
import { secretMethods } from "./secret.js";
import type { Registry } from "./types.js";
import { vaultMethods } from "./vault.js";

/**
 * Every RPC method. Nothing here returns secret bytes: `helper.get` (Task 12) is the one method
 * that may set `returnsSecret`, and the registry test fails if any other does.
 */
export const registry: Registry = Object.freeze({
  ...vaultMethods,
  ...secretMethods,
  ...bundleMethods,
  ...auditMethods,
});

export type { Ctx, DaemonState, MethodDef, Registry } from "./types.js";
