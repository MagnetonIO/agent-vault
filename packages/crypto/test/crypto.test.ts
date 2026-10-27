import { describe, expect, test } from "vitest";
import {
  DecryptError,
  deriveKeyfileKey,
  deriveSubkey,
  encodeAad,
  keyFromRecoveryWords,
  mac,
  macEqual,
  open,
  randomKey,
  recoveryWords,
  seal,
} from "../src/index.js";

const aad = (over: Partial<Parameters<typeof encodeAad>[0]> = {}) =>
  encodeAad({
    vaultId: "v1",
    table: "secrets",
    recordId: "r1",
    field: "value",
    version: 1,
    ...over,
  });

const enc = (s: string) => new TextEncoder().encode(s);

describe("aead", () => {
  test("roundtrip", () => {
    const k = randomKey();
    const pt = enc("hunter2");
    expect(open(k, seal(k, pt, aad()), aad())).toEqual(pt);
  });

  test("randomKey is 32 bytes and not constant", () => {
    expect(randomKey()).toHaveLength(32);
    expect(randomKey()).not.toEqual(randomKey());
  });

  test("sealed layout is nonce(24) || ciphertext || tag(16)", () => {
    const k = randomKey();
    expect(seal(k, enc("abc"), aad())).toHaveLength(24 + 3 + 16);
  });

  test("aad mismatch throws", () => {
    const k = randomKey();
    const sealed = seal(k, enc("x"), aad({ version: 1 }));
    expect(() => open(k, sealed, aad({ version: 2 }))).toThrow(DecryptError);
  });

  test("row swap throws", () => {
    const k = randomKey();
    const sealed = seal(k, enc("x"), aad({ recordId: "r1" }));
    expect(() => open(k, sealed, aad({ recordId: "r2" }))).toThrow(DecryptError);
  });

  test("wrong key throws", () => {
    const sealed = seal(randomKey(), enc("x"), aad());
    expect(() => open(randomKey(), sealed, aad())).toThrow(DecryptError);
  });

  test("tampered ciphertext throws", () => {
    const k = randomKey();
    const sealed = seal(k, enc("secret"), aad());
    sealed[30] = (sealed[30] ?? 0) ^ 1;
    expect(() => open(k, sealed, aad())).toThrow(DecryptError);
  });

  test("truncated input throws DecryptError", () => {
    const k = randomKey();
    const sealed = seal(k, enc("secret"), aad());
    expect(() => open(k, sealed.subarray(0, 10), aad())).toThrow(DecryptError);
    expect(() => open(k, sealed.subarray(0, 30), aad())).toThrow(DecryptError);
    expect(() => open(k, new Uint8Array(0), aad())).toThrow(DecryptError);
  });

  test("nonce unique", () => {
    const k = randomKey();
    const nonces = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      nonces.add(Buffer.from(seal(k, enc("x"), aad()).subarray(0, 24)).toString("hex"));
    }
    expect(nonces.size).toBe(1000);
  });
});

describe("encodeAad", () => {
  test("unambiguous", () => {
    expect(aad({ table: "ab", recordId: "c" })).not.toEqual(aad({ table: "a", recordId: "bc" }));
  });

  test("layout: u32 BE length + utf8 per part, then u64 BE version", () => {
    const out = encodeAad({ vaultId: "v", table: "t", recordId: "é", field: "f", version: 258 });
    const expected = Buffer.concat([
      Buffer.from([0, 0, 0, 1, 0x76]),
      Buffer.from([0, 0, 0, 1, 0x74]),
      Buffer.from([0, 0, 0, 2, 0xc3, 0xa9]),
      Buffer.from([0, 0, 0, 1, 0x66]),
      Buffer.from([0, 0, 0, 0, 0, 0, 1, 2]),
    ]);
    expect(Buffer.from(out)).toEqual(expected);
  });

  test("rejects negative, fractional and non-finite versions", () => {
    expect(() => aad({ version: -1 })).toThrow();
    expect(() => aad({ version: 1.5 })).toThrow();
    expect(() => aad({ version: Number.NaN })).toThrow();
    expect(() => aad({ version: Number.POSITIVE_INFINITY })).toThrow();
    expect(() => aad({ version: 2 ** 53 })).toThrow();
  });
});

describe("hkdf / hmac", () => {
  test("subkeys are 32 bytes, deterministic, and domain-separated", () => {
    const k = randomKey();
    const enc1 = deriveSubkey(k, "enc");
    expect(enc1).toHaveLength(32);
    expect(deriveSubkey(k, "enc")).toEqual(enc1);
    expect(deriveSubkey(k, "mac")).not.toEqual(enc1);
    expect(deriveSubkey(k, "audit")).not.toEqual(deriveSubkey(k, "mac"));
    expect(enc1).not.toEqual(k);
  });

  test("hmac-sha256 matches RFC 4231 test case 2", () => {
    const out = mac(enc("Jefe"), enc("what do ya want for nothing?"));
    expect(Buffer.from(out).toString("hex")).toBe(
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    );
  });

  test("macEqual is true only for identical bytes", () => {
    const a = mac(randomKey(), enc("m"));
    expect(macEqual(a, a.slice())).toBe(true);
    const b = a.slice();
    b[0] = (b[0] ?? 0) ^ 1;
    expect(macEqual(a, b)).toBe(false);
    expect(macEqual(a, a.subarray(0, 31))).toBe(false);
  });
});

describe("recovery words", () => {
  test("recovery roundtrip", () => {
    const k = randomKey();
    const words = recoveryWords(k);
    expect(words).toHaveLength(24);
    expect(keyFromRecoveryWords(words)).toEqual(k);
  });

  test("known vector: all-zero key", () => {
    expect(recoveryWords(new Uint8Array(32)).join(" ")).toBe(`${"abandon ".repeat(23)}art`);
  });

  test("bad checksum", () => {
    const words = recoveryWords(randomKey());
    // Replacing the last word with a different valid word breaks the checksum
    // for all but 1/256 candidates; try two to avoid that rare collision.
    const bad = [words.slice(0, 23), words.slice(0, 23)];
    bad[0]?.push(words[23] === "abandon" ? "ability" : "abandon");
    bad[1]?.push(words[23] === "zoo" ? "zone" : "zoo");
    const failures = bad.filter((w) => {
      try {
        keyFromRecoveryWords(w);
        return false;
      } catch {
        return true;
      }
    });
    expect(failures.length).toBeGreaterThanOrEqual(1);
  });

  test("unknown word throws", () => {
    const words = recoveryWords(randomKey());
    words[3] = "notaword";
    expect(() => keyFromRecoveryWords(words)).toThrow();
  });

  test("wrong word count throws", () => {
    expect(() => keyFromRecoveryWords(recoveryWords(randomKey()).slice(0, 12))).toThrow();
  });

  test("recoveryWords rejects non-32-byte keys", () => {
    expect(() => recoveryWords(new Uint8Array(16))).toThrow();
  });
});

describe("keyfile kdf", () => {
  test("argon2id is deterministic and 32 bytes", () => {
    const salt = new Uint8Array(16).fill(7);
    const a = deriveKeyfileKey("correct horse", salt);
    expect(a).toHaveLength(32);
    expect(deriveKeyfileKey("correct horse", salt)).toEqual(a);
  }, 30_000);
});
