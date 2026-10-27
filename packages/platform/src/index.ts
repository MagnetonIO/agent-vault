export type { IpcEndpoint } from "./ipc-endpoint.js";
export { ipcEndpoint } from "./ipc-endpoint.js";
export type { RootKeyStore } from "./keystore.js";
export {
  KeyfileCorruptError,
  KeyringUnavailableError,
  KeyringValueInvalidError,
  MemoryKeyStore,
  mapKeyringError,
  openKeyfileStore,
  openOsKeyring,
  WrongPassphraseError,
} from "./keystore.js";
export { childBaseEnv, PASSPHRASE_ENV } from "./passphrase-env.js";
export type { VaultPaths } from "./paths.js";
export { getPaths } from "./paths.js";
export { ensurePrivateDir, icaclsCommands, icaclsExe } from "./private-dir.js";
