import { helperMethods } from "../helper.js";
import { auditMethods } from "./audit.js";
import { bundleMethods } from "./bundle.js";
import { captureMethods } from "./capture.js";
import { daemonMethods } from "./daemon.js";
import { runMethods } from "./run.js";
import { scrubMethods } from "./scrub.js";
import { secretMethods } from "./secret.js";
import type { Registry } from "./types.js";
import { vaultMethods } from "./vault.js";

/**
 * Every RPC method. Nothing here returns secret bytes except `helper.get`, the one method that
 * may set `returnsSecret` (and only for secrets tagged `helper`); the registry test fails if any
 * other does. `run.start` sends the child's output, redacted.
 */
export const registry: Registry = Object.freeze({
  ...vaultMethods,
  ...daemonMethods,
  ...secretMethods,
  ...bundleMethods,
  ...auditMethods,
  ...captureMethods,
  ...runMethods,
  ...helperMethods,
  ...scrubMethods,
});

export type { Ctx, DaemonState, MethodDef, Registry } from "./types.js";
