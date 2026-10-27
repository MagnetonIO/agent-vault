import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DecryptError, deriveKeyfileKey, encodeAad, open, seal } from "@agent-vault/crypto";
import { Entry } from "@napi-rs/keyring";

export interface RootKeyStore {
  readonly kind: "os-keyring" | "keyfile" | "memory";
  load(): Promise<Uint8Array | null>;
  save(k: Uint8Array): Promise<void>;
  remove(): Promise<void>;
}

export class KeyringUnavailableError extends Error {
  constructor() {
    super("No Secret Service found. Run: agent-vault init --keystore keyfile");
    this.name = "KeyringUnavailableError";
  }
}

export class WrongPassphraseError extends Error {
  constructor() {
    super("wrong passphrase, or the keyfile was modified");
    this.name = "WrongPassphraseError";
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
  return SECRET_SERVICE_DOWN.some((s) => message.includes(s)) ? new KeyringUnavailableError() : err;
}

const SERVICE = "agent-vault";
const DEVICE_ROOT_KEY = "device-root-key";

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
      return b64 === null || b64 === undefined ? null : Uint8Array.from(Buffer.from(b64, "base64"));
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
  salt: string;
  sealed: string;
}

function parseKeyfile(text: string): KeyfileJson {
  let j: unknown;
  try {
    j = JSON.parse(text);
  } catch {
    throw new Error("keyfile is not valid JSON");
  }
  const o = j as Partial<KeyfileJson> | null;
  if (o?.v !== 1 || typeof o.salt !== "string" || typeof o.sealed !== "string") {
    throw new Error("keyfile has an unsupported format");
  }
  return o as KeyfileJson;
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
      const key = deriveKeyfileKey(passphrase, Buffer.from(salt, "base64"));
      try {
        return open(key, Buffer.from(sealed, "base64"), KEYFILE_AAD);
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
      const json: KeyfileJson = {
        v: 1,
        salt: salt.toString("base64"),
        sealed: Buffer.from(sealed).toString("base64"),
      };
      const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.tmp`);
      try {
        fs.rmSync(tmp, { force: true });
        fs.writeFileSync(tmp, `${JSON.stringify(json)}\n`, { mode: 0o600, flag: "wx" });
        fs.renameSync(tmp, file);
      } catch (err) {
        fs.rmSync(tmp, { force: true });
        throw err;
      }
    },
    async remove() {
      fs.rmSync(file, { force: true });
    },
  };
}
