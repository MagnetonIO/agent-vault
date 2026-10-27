import { argon2id } from "@noble/hashes/argon2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";

export type SubkeyInfo = "enc" | "mac" | "audit";

const KEY_LEN = 32;

/** HKDF-SHA-256 with no salt; `info` provides domain separation. */
export function deriveSubkey(key: Uint8Array, info: SubkeyInfo): Uint8Array {
  return hkdf(sha256, key, undefined, new TextEncoder().encode(`agent-vault/${info}`), KEY_LEN);
}

/** HMAC-SHA-256. */
export function mac(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

/** Constant-time comparison; length is not secret. */
export function macEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

/** Argon2id, m=64 MiB, t=3, p=1. Passphrase is NFKC-normalized so equivalent Unicode forms match. */
export function deriveKeyfileKey(passphrase: string, salt: Uint8Array): Uint8Array {
  return argon2id(passphrase.normalize("NFKC"), salt, { m: 65536, t: 3, p: 1, dkLen: KEY_LEN });
}
