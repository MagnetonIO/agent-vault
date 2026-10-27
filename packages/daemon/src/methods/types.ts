import type { Vault } from "@agent-vault/core";
import type { RootKeyStore, VaultPaths } from "@agent-vault/platform";
import type { CaptureService } from "../capture-page.js";

/** What the daemon holds between calls. `vault` is null until `vault.init` has run. */
export type DaemonState = {
  vault: Vault | null;
  initializing: boolean;
  closed: boolean;
};

/** What a mutating handler tells the audit log about the call. Names only, never values. */
export type AuditFields = {
  secretName?: string | undefined;
  bundle?: string | undefined;
};

export type Ctx = {
  readonly paths: VaultPaths;
  readonly store: RootKeyStore;
  readonly state: DaemonState;
  /** The one-time loopback capture page (Task 11). */
  readonly capture: CaptureService;
  readonly audit: AuditFields;
  /** The open vault; throws VaultNotInitializedError before `vault.init`. */
  vault(): Vault;
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
