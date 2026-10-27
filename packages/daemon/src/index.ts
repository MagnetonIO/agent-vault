export { type EnsureDaemonOptions, ensureDaemon } from "./autostart.js";
export { type ConnectOptions, connect, type IpcClient } from "./client.js";
export { DaemonAlreadyRunningError, DaemonIdentityError, RpcError } from "./errors.js";
export { type DaemonHandle, type StartDaemonOptions, startDaemon } from "./server.js";
