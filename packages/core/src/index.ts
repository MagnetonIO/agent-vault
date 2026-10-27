export type { Db, Statement } from "./db.js";
export { openDb } from "./db.js";
export {
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
export type { SecretMeta } from "./vault.js";
export { initVault, openVault, recoverVault, Vault } from "./vault.js";
