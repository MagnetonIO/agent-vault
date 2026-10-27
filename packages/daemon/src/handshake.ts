import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Mutual, channel-bound token handshake for the tcp endpoint (Spike S2, plus both nonces in each
 * MAC). All lines are `\n`-terminated ASCII; the token never crosses the wire.
 *
 *   1. client -> nonce_c
 *   2. server -> hex(HMAC(token, "srv" || port || nonce_c || nonce_s)) + " " + nonce_s
 *   3. client verifies in constant time and sends nothing else until it passes
 *   4. client -> hex(HMAC(token, "cli" || port || nonce_s || nonce_c)); JSON-RPC lines may follow
 *
 * HMAC key = the raw token bytes. Message = the ASCII label, the decimal ASCII port and the ASCII
 * hex nonces, concatenated. The server's port is the one it listens on and the client's is the
 * one it dialed, so a relay on another port cannot pass the handshake through to the daemon.
 */
export const HANDSHAKE_LINE_MAX = 200;
export const HANDSHAKE_STEP_TIMEOUT_MS = 1500;

export const HEX64 = /^[0-9a-f]{64}$/;
export const SERVER_REPLY = /^([0-9a-f]{64}) ([0-9a-f]{64})$/;

export const newNonce = (): string => randomBytes(32).toString("hex");

export function handshakeMac(
  token: Buffer,
  label: "srv" | "cli",
  port: number,
  first: string,
  second: string,
): string {
  return createHmac("sha256", token).update(`${label}${port}${first}${second}`).digest("hex");
}

/** Constant-time compare of two hex strings. Their lengths are public. */
export function macMatches(a: string, b: string): boolean {
  return a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

/** The raw token bytes from a token file's text, or null if it is not 64 hex characters. */
export function parseToken(text: string): Buffer | null {
  const hex = text.trim();
  return HEX64.test(hex) ? Buffer.from(hex, "hex") : null;
}
