export type { AuditEvent, AuditInput } from "./audit.js";
export { appendAudit, queryAudit, verifyAudit } from "./audit.js";
export type { BundleInfo } from "./bundles.js";
export { allowExe, createBundle, grant, listBundles, resolveBundle } from "./bundles.js";
export type { Db, Statement } from "./db.js";
export { openDb } from "./db.js";
export {
  AuditEventInvalidError,
  BundleExistsError,
  BundleNotFoundError,
  InvalidEnvNameError,
  InvalidExePathError,
  InvalidNameError,
  MetadataTamperError,
  RecoveryFailedError,
  RootKeyMissingError,
  SecretNotFoundError,
  UnsupportedSchemaError,
  VaultClosedError,
  VaultExistsError,
  VaultNotInitializedError,
} from "./errors.js";
export { SCHEMA_VERSION } from "./migrations.js";
export type { EnvEntry } from "./refs.js";
export { parseEnvFile, parseRef } from "./refs.js";
export type { ScrubRow } from "./scrub-queue.js";
export { deleteScrubRows, enqueueScrub, listScrubQueue } from "./scrub-queue.js";
export type { SecretMeta } from "./vault.js";
export { initVault, openVault, recoverVault, Vault } from "./vault.js";
