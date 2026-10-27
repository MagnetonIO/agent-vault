import type { Vault } from "@agent-vault/core";
import type { RootKeyStore, VaultPaths } from "@agent-vault/platform";
import type { CaptureService } from "../capture-page.js";
import type { Connection } from "../connection.js";
import type { RunnerService } from "../runner.js";

/** What the daemon holds between calls. `vault` is null until `vault.init` or `vault.recover` has run. */
export type DaemonState = {
  vault: Vault | null;
  initializing: boolean;
  /** A vault exists on disk but this device's root key is missing (see `vault.recover`). */
  locked: boolean;
  closed: boolean;
};

/** What a mutating handler tells the audit log about the call. Names only, never values. */
export type AuditFields = {
  secretName?: string | undefined;
  bundle?: string | undefined;
  /** Set before throwing to log a refusal as `blocked` instead of `error`. */
  failure?: "blocked" | undefined;
};

export type Ctx = {
  readonly paths: VaultPaths;
  readonly store: RootKeyStore;
  readonly state: DaemonState;
  /** The one-time loopback capture page (Task 11). */
  readonly capture: CaptureService;
  /** The child processes `run.start` launched (Task 12). */
  readonly runner: RunnerService;
  /** The connection making this call; runs belong to the one that started them. */
  readonly connection: Connection;
  readonly audit: AuditFields;
  /** The open vault; throws VaultNotInitializedError before `vault.init`, VaultLockedError when locked. */
  vault(): Vault;
  /** Close the daemon once the reply to this call has been written. */
  requestStop(): void;
  /** Send a JSON-RPC notification to the connection that made this call. */
  notify(method: string, params: unknown): void;
};

export type MethodDef = {
  handler: (ctx: Ctx, params: unknown) => unknown;
  /** Writes an audit event for every call. */
  mutates: boolean;
  /** Returns secret bytes. Only `helper.get` may be true. */
  returnsSecret: boolean;
};

export type Registry = Readonly<Record<string, MethodDef>>;
