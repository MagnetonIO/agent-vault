import {
  AuditEventInvalidError,
  type AuditInput,
  appendAudit,
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
} from "@agent-vault/core";
import {
  KeyfileCorruptError,
  KeyringUnavailableError,
  KeyringValueInvalidError,
  type RootKeyStore,
  type VaultPaths,
  WrongPassphraseError,
} from "@agent-vault/platform";
import type { CaptureService } from "./capture-page.js";
import type { Connection } from "./connection.js";
import { deviceId, harnessOf } from "./device.js";
import {
  ExeNotAllowedError,
  HelperNotAllowedError,
  RpcError,
  RunError,
  SecretNotTextError,
} from "./errors.js";
import type { Ctx, DaemonState, Registry } from "./methods/index.js";
import { ERR, type JsonRpcErrorObject } from "./rpc.js";
import type { RunnerService } from "./runner.js";

/** Errors whose own message is safe to put on the wire. Their messages never carry values or keys. */
const APP_ERRORS: readonly (abstract new (...args: never[]) => Error)[] = [
  AuditEventInvalidError,
  BundleExistsError,
  BundleNotFoundError,
  InvalidEnvNameError,
  InvalidExePathError,
  InvalidNameError,
  KeyfileCorruptError,
  KeyringUnavailableError,
  KeyringValueInvalidError,
  MetadataTamperError,
  RecoveryFailedError,
  RootKeyMissingError,
  SecretNotFoundError,
  UnsupportedSchemaError,
  VaultClosedError,
  VaultExistsError,
  VaultNotInitializedError,
  WrongPassphraseError,
  ExeNotAllowedError,
  HelperNotAllowedError,
  RunError,
  SecretNotTextError,
];

/** Before `vault.init` only these work. */
const WORKS_UNINITIALIZED: ReadonlySet<string> = new Set(["status", "vault.init"]);

/** The wire form of a thrown error. Never a stack, and only the messages of known error classes. */
export function toErrorObject(err: unknown): JsonRpcErrorObject {
  if (err instanceof RpcError) {
    return {
      code: err.code,
      message: err.message,
      ...(err.data !== undefined && { data: err.data }),
    };
  }
  if (err instanceof Error && APP_ERRORS.some((cls) => err instanceof cls)) {
    return { code: ERR.APP, message: err.message, data: { name: err.name } };
  }
  return {
    code: ERR.INTERNAL,
    message: "internal error",
    data: { name: err instanceof Error ? err.name : "Error" },
  };
}

export type CallResult = { ok: true; result: unknown } | { ok: false; error: JsonRpcErrorObject };

export type Dispatcher = (
  method: string,
  params: unknown,
  notify: (method: string, params: unknown) => void,
  connection: Connection,
) => Promise<CallResult>;

type Deps = {
  registry: Registry;
  state: DaemonState;
  paths: VaultPaths;
  store: RootKeyStore;
  capture: CaptureService;
  runner: RunnerService;
};

export function createDispatcher({
  registry,
  state,
  paths,
  store,
  capture,
  runner,
}: Deps): Dispatcher {
  function record(method: string, params: unknown, ctx: Ctx, outcome: AuditInput["outcome"]) {
    if (!state.vault) return;
    appendAudit(state.vault, {
      deviceId,
      harness: harnessOf(params),
      actor: "rpc",
      ...(ctx.audit.secretName !== undefined && { secretName: ctx.audit.secretName }),
      ...(ctx.audit.bundle !== undefined && { bundle: ctx.audit.bundle }),
      operation: method,
      outcome,
    });
  }

  async function run(
    method: string,
    params: unknown,
    notify: (method: string, params: unknown) => void,
    connection: Connection,
  ): Promise<unknown> {
    const def = Object.hasOwn(registry, method) ? registry[method] : undefined;
    if (!def) throw new RpcError(ERR.METHOD_NOT_FOUND, "method not found");
    if (!state.vault && !WORKS_UNINITIALIZED.has(method)) throw new VaultNotInitializedError();

    const ctx: Ctx = {
      paths,
      store,
      state,
      capture,
      runner,
      connection,
      audit: {},
      vault() {
        if (!state.vault) throw new VaultNotInitializedError();
        return state.vault;
      },
      notify,
    };
    if (!def.mutates) return def.handler(ctx, params);

    let result: unknown;
    try {
      result = await def.handler(ctx, params);
    } catch (err) {
      try {
        record(method, params, ctx, ctx.audit.failure ?? "error");
      } catch {
        // The handler's error is the one the caller needs; a failed audit append must not hide it.
      }
      throw err;
    }
    // A mutation that committed but could not be logged is reported as a failure.
    record(method, params, ctx, method === "secret.put" ? "captured" : "brokered");
    return result;
  }

  return async (method, params, notify, connection) => {
    try {
      return { ok: true, result: await run(method, params, notify, connection) };
    } catch (err) {
      return { ok: false, error: toErrorObject(err) };
    }
  };
}
