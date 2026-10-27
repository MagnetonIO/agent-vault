const MAX_NAME_IN_MESSAGE = 128;

/** A vault already exists at this location. */
export class VaultExistsError extends Error {
  constructor() {
    super("a vault already exists here");
    this.name = "VaultExistsError";
  }
}

/** There is no vault at this location (no db file, or no meta row). */
export class VaultNotInitializedError extends Error {
  constructor() {
    super("no vault has been initialized here");
    this.name = "VaultNotInitializedError";
  }
}

/** The vault was written by a newer version than this code understands. */
export class UnsupportedSchemaError extends Error {
  constructor(version: number) {
    super(`vault schema version ${version} is not supported`);
    this.name = "UnsupportedSchemaError";
  }
}

/** The key store has no device root key, or the one it has does not unwrap the data key. */
export class RootKeyMissingError extends Error {
  /** `cause` is the DecryptError when the key was present but wrong. */
  constructor(cause?: unknown) {
    super("device root key is missing or does not match this vault", { cause });
    this.name = "RootKeyMissingError";
  }
}

/** The recovery words do not unlock this vault. The message never repeats the words. */
export class RecoveryFailedError extends Error {
  constructor(cause?: unknown) {
    super("recovery words are not valid for this vault", { cause });
    this.name = "RecoveryFailedError";
  }
}

/** The name is not a legal secret name. The message carries the name and nothing else. */
export class InvalidNameError extends Error {
  constructor(name: string) {
    const shown =
      name.length > MAX_NAME_IN_MESSAGE ? `${name.slice(0, MAX_NAME_IN_MESSAGE)}...` : name;
    super(`invalid secret name: ${JSON.stringify(shown)}`);
    this.name = "InvalidNameError";
  }
}

export class SecretNotFoundError extends Error {
  constructor(name: string) {
    super(`secret not found: ${JSON.stringify(name)}`);
    this.name = "SecretNotFoundError";
  }
}

/** A row's stored metadata no longer matches its MAC: it was edited outside the vault. */
export class MetadataTamperError extends Error {
  /** `kind` says what the row is: "secret" (default), "bundle" or "audit entry". */
  constructor(name: string, kind = "secret") {
    super(`metadata for ${kind} ${JSON.stringify(name)} failed integrity check`);
    this.name = "MetadataTamperError";
  }
}

/** The vault was closed; its keys are zeroed and it cannot be used again. */
export class VaultClosedError extends Error {
  constructor() {
    super("vault is closed");
    this.name = "VaultClosedError";
  }
}

/** The bundle name is legal but no such bundle exists. */
export class BundleNotFoundError extends Error {
  constructor(name: string) {
    super(`bundle not found: ${JSON.stringify(name)}`);
    this.name = "BundleNotFoundError";
  }
}

/** `createBundle` was called with a name already in use. */
export class BundleExistsError extends Error {
  constructor(name: string) {
    super(`bundle already exists: ${JSON.stringify(name)}`);
    this.name = "BundleExistsError";
  }
}

/** The env var name is not `[A-Za-z_][A-Za-z0-9_]*`. */
export class InvalidEnvNameError extends Error {
  constructor(name: string) {
    const shown =
      name.length > MAX_NAME_IN_MESSAGE ? `${name.slice(0, MAX_NAME_IN_MESSAGE)}...` : name;
    super(`invalid env name: ${JSON.stringify(shown)}`);
    this.name = "InvalidEnvNameError";
  }
}

/** An allowed executable must be given as an absolute path. */
export class InvalidExePathError extends Error {
  constructor(exePath: string) {
    const shown =
      exePath.length > MAX_NAME_IN_MESSAGE
        ? `${exePath.slice(0, MAX_NAME_IN_MESSAGE)}...`
        : exePath;
    super(`executable path must be absolute: ${JSON.stringify(shown)}`);
    this.name = "InvalidExePathError";
  }
}

/**
 * An audit event or query was malformed. The message names the offending field and why, never its
 * value: a caller that put a secret in the wrong field must not see it copied into an error log.
 */
export class AuditEventInvalidError extends Error {
  constructor(field: string, reason: string) {
    const shown =
      field.length > MAX_NAME_IN_MESSAGE ? `${field.slice(0, MAX_NAME_IN_MESSAGE)}...` : field;
    super(`invalid audit event: field ${JSON.stringify(shown)} ${reason}`);
    this.name = "AuditEventInvalidError";
  }
}
