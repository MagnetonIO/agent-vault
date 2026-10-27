export { type EnsureDaemonOptions, ensureDaemon } from "./autostart.js";
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
