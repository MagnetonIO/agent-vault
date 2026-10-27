export {
  type DaemonRunArgvOptions,
  daemonRunArgv,
  type EnsureDaemonOptions,
  ensureDaemon,
} from "./autostart.js";
export { openUrl } from "./capture-page.js";
export { type CallOptions, type ConnectOptions, connect, type IpcClient } from "./client.js";
export {
  DaemonAlreadyRunningError,
  DaemonExitedError,
  DaemonIdentityError,
  RecoveryInProgressError,
  RpcError,
} from "./errors.js";
export { acquireRecoverLock, recoverLockPath, recoveryInProgress } from "./lock.js";
export { type DaemonHandle, type StartDaemonOptions, startDaemon } from "./server.js";
export {
  type CommandRunner,
  type InstallOptions,
  installService,
  ServiceError,
  type ServiceOptions,
  type ServiceResult,
  uninstallService,
} from "./service/index.js";
