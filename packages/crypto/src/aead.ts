import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes } from "@noble/ciphers/utils.js";

const NONCE_LEN = 24;
const TAG_LEN = 16;
const KEY_LEN = 32;
const U32_MAX = 0xffff_ffff;

export class DecryptError extends Error {
  constructor() {
    super("decryption failed");
    this.name = "DecryptError";
  }
}

export interface AadParts {
  vaultId: string;
  table: string;
  recordId: string;
  field: string;
  version: number;
}

export function randomKey(): Uint8Array {
  return randomBytes(KEY_LEN);
}

/**
 * vaultId ‖ table ‖ recordId ‖ field, each as u32 BE length + UTF-8 bytes,
 * followed by version as u64 BE. Length prefixes make the encoding unambiguous.
 */
export function encodeAad(p: AadParts): Uint8Array {
  if (!Number.isSafeInteger(p.version) || p.version < 0) {
    throw new RangeError("aad version must be a non-negative safe integer");
  }
  const enc = new TextEncoder();
  const parts = [p.vaultId, p.table, p.recordId, p.field].map((s) => enc.encode(s));
  const out = new Uint8Array(parts.reduce((n, b) => n + 4 + b.length, 8));
  const view = new DataView(out.buffer);
  let off = 0;
  for (const b of parts) {
    if (b.length > U32_MAX) throw new RangeError("aad part too long");
    view.setUint32(off, b.length);
    out.set(b, off + 4);
    off += 4 + b.length;
  }
  view.setBigUint64(off, BigInt(p.version));
  return out;
}

/** Returns nonce(24) ‖ ciphertext ‖ tag(16). */
export function seal(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Uint8Array {
  const nonce = randomBytes(NONCE_LEN);
  const ct = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  const out = new Uint8Array(NONCE_LEN + ct.length);
  out.set(nonce, 0);
  out.set(ct, NONCE_LEN);
  return out;
}

/** Throws DecryptError on any failure (tamper, wrong key or AAD, truncation). */
export function open(key: Uint8Array, sealed: Uint8Array, aad: Uint8Array): Uint8Array {
  if (sealed.length < NONCE_LEN + TAG_LEN) throw new DecryptError();
  try {
    return xchacha20poly1305(key, sealed.subarray(0, NONCE_LEN), aad).decrypt(
      sealed.subarray(NONCE_LEN),
    );
  } catch {
    throw new DecryptError();
  }
}
