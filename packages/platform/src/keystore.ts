import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DecryptError, deriveKeyfileKey, encodeAad, open, seal } from "@agent-vault/crypto";
import { Entry } from "@napi-rs/keyring";
import { ensurePrivateDir } from "./private-dir.js";

export interface RootKeyStore {
  readonly kind: "os-keyring" | "keyfile" | "memory";
  load(): Promise<Uint8Array | null>;
  save(k: Uint8Array): Promise<void>;
  remove(): Promise<void>;
}

export class KeyringUnavailableError extends Error {
  /** `cause` is the original keyring error, for diagnosis; the message is fixed. */
  constructor(cause?: unknown) {
    super("No Secret Service found. Run: agent-vault init --keystore keyfile", { cause });
    this.name = "KeyringUnavailableError";
  }
}

/** The keyring entry exists but does not hold a 32-byte key. Reports sizes only, never bytes. */
export class KeyringValueInvalidError extends Error {
  constructor(reason: string) {
    super(`OS keyring entry for the device root key is invalid: ${reason}`);
    this.name = "KeyringValueInvalidError";
  }
}

export class WrongPassphraseError extends Error {
  constructor() {
    super("wrong passphrase, or the keyfile was modified");
    this.name = "WrongPassphraseError";
  }
}

/** The keyfile cannot be parsed or is structurally invalid; not a passphrase problem. */
export class KeyfileCorruptError extends Error {
  constructor(reason: string) {
    super(`keyfile is corrupt: ${reason}`);
    this.name = "KeyfileCorruptError";
  }
}

/** Test double. Copies on the way in and out so callers can zero their buffers. */
export class MemoryKeyStore implements RootKeyStore {
  readonly kind = "memory";
  #key: Uint8Array | null = null;

  async load(): Promise<Uint8Array | null> {
    return this.#key ? Uint8Array.from(this.#key) : null;
  }

  async save(k: Uint8Array): Promise<void> {
    this.#key = Uint8Array.from(k);
  }

  async remove(): Promise<void> {
    this.#key = null;
  }
}

// What a pinned Linux Entry throws when there is no usable Secret Service (Spike S1).
const SECRET_SERVICE_DOWN = [
  "unlock prompt was dismissed", // bus exists, keyring locked
  "DBus error: Failed to connect to socket", // no bus
  "Secret Service: no result found", // no usable default collection
];

/** The typed error for the known "no Secret Service" failures; anything else is returned as is. */
export function mapKeyringError(err: unknown): unknown {
  const message = err instanceof Error ? err.message : String(err);
  return SECRET_SERVICE_DOWN.some((s) => message.includes(s))
    ? new KeyringUnavailableError(err)
    : err;
}

const SERVICE = "agent-vault";
const DEVICE_ROOT_KEY = "device-root-key";
const ROOT_KEY_LEN = 32;

/**
 * The device root key in the OS credential store, stored as base64. On Linux the Entry is pinned
 * to Secret Service: unpinned, an unreachable Secret Service silently falls back to the kernel
 * keyutils keyring, which does not survive a reboot. `account` is for tests only.
 */
export function openOsKeyring(account: string = DEVICE_ROOT_KEY): RootKeyStore {
  const entry = () => new Entry(SERVICE, account, { linux: { store: "secret-service" } });
  const guard = <T>(fn: () => T): T => {
    try {
      return fn();
    } catch (err) {
      throw mapKeyringError(err);
    }
  };
  return {
    kind: "os-keyring",
    async load() {
      const b64 = guard(() => entry().getPassword());
      if (b64 === null || b64 === undefined) return null;
      const key = Buffer.from(b64, "base64");
      if (key.toString("base64") !== b64) throw new KeyringValueInvalidError("not valid base64");
      if (key.length !== ROOT_KEY_LEN) {
        throw new KeyringValueInvalidError(`expected ${ROOT_KEY_LEN} bytes, found ${key.length}`);
      }
      return Uint8Array.from(key);
    },
    async save(k) {
      guard(() => entry().setPassword(Buffer.from(k).toString("base64")));
    },
    async remove() {
      guard(() => entry().deletePassword());
    },
  };
}

const KEYFILE_AAD = encodeAad({
  vaultId: "keyfile",
  table: "keyfile",
  recordId: "device-root-key",
  field: "key",
  version: 1,
});

interface KeyfileJson {
  v: 1;
  salt: Uint8Array;
  sealed: Uint8Array;
}

const SALT_MIN = 16;
const NONCE_LEN = 24;
const TAG_LEN = 16;

/** Strict base64: only the canonical encoding of the bytes is accepted. */
function b64(value: unknown, field: string): Uint8Array {
  if (typeof value !== "string") throw new KeyfileCorruptError(`${field} is missing`);
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) throw new KeyfileCorruptError(`${field} is not base64`);
  return Uint8Array.from(bytes);
}

function parseKeyfile(text: string): KeyfileJson {
  let j: unknown;
  try {
    j = JSON.parse(text);
  } catch {
    throw new KeyfileCorruptError("not valid JSON");
  }
  const o = (typeof j === "object" ? j : null) as Record<string, unknown> | null;
  if (o?.v !== 1) throw new KeyfileCorruptError("unsupported version");
  const salt = b64(o.salt, "salt");
  if (salt.length < SALT_MIN) throw new KeyfileCorruptError("salt is too short");
  const sealed = b64(o.sealed, "sealed");
  if (sealed.length < NONCE_LEN + TAG_LEN)
    throw new KeyfileCorruptError("sealed data is too short");
  return { v: 1, salt, sealed };
}

/** temp file (0600) + fsync + rename + best-effort fsync of the parent dir. */
function writeFileAtomic(file: string, data: string): void {
  const dir = path.dirname(file);
  const tmp = path.join(dir, `.${path.basename(file)}.${process.pid}.tmp`);
  try {
    fs.rmSync(tmp, { force: true });
    const fd = fs.openSync(tmp, "wx", 0o600);
    try {
      fs.writeFileSync(fd, data);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
  if (process.platform !== "win32") {
    try {
      const dfd = fs.openSync(dir, "r");
      try {
        fs.fsyncSync(dfd);
      } finally {
        fs.closeSync(dfd);
      }
    } catch {
      // durability of the rename only; the file itself is already in place
    }
  }
}

/**
 * Fallback when no Secret Service exists: the root key sealed under an Argon2id key derived from
 * a passphrase. Weaker than the OS keyring (an offline attacker can grind the passphrase), so
 * callers should say so. The file is written 0600 via temp file + rename.
 */
export function openKeyfileStore(file: string, passphrase: string): RootKeyStore {
  return {
    kind: "keyfile",
    async load() {
      let text: string;
      try {
        text = fs.readFileSync(file, "utf8");
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
        throw err;
      }
      const { salt, sealed } = parseKeyfile(text);
      let key: Uint8Array;
      try {
        key = deriveKeyfileKey(passphrase, salt);
      } catch {
        throw new KeyfileCorruptError("key derivation failed");
      }
      try {
        return open(key, sealed, KEYFILE_AAD);
      } catch (err) {
        if (err instanceof DecryptError) throw new WrongPassphraseError();
        throw err;
      } finally {
        key.fill(0);
      }
    },
    async save(k) {
      const salt = randomBytes(16);
      const key = deriveKeyfileKey(passphrase, salt);
      let sealed: Uint8Array;
      try {
        sealed = seal(key, k, KEYFILE_AAD);
      } finally {
        key.fill(0);
      }
      ensurePrivateDir(path.dirname(file));
      writeFileAtomic(
        file,
        `${JSON.stringify({
          v: 1,
          salt: salt.toString("base64"),
          sealed: Buffer.from(sealed).toString("base64"),
        })}\n`,
      );
    },
    async remove() {
      fs.rmSync(file, { force: true });
    },
  };
}
