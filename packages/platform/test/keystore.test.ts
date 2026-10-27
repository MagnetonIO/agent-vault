import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { randomKey } from "@agent-vault/crypto";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import {
  KeyfileCorruptError,
  KeyringUnavailableError,
  MemoryKeyStore,
  mapKeyringError,
  openKeyfileStore,
  openOsKeyring,
  WrongPassphraseError,
} from "../src/index.js";

let tmp: string;
beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "av-keystore-"));
});
afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe("MemoryKeyStore", () => {
  test("round-trips, copies on save and load, removes", async () => {
    const s = new MemoryKeyStore();
    expect(s.kind).toBe("memory");
    expect(await s.load()).toBeNull();
    const k = randomKey();
    await s.save(k);
    const orig = Uint8Array.from(k);
    k.fill(0);
    const got = await s.load();
    expect(got).toEqual(orig);
    got?.fill(0);
    expect(await s.load()).toEqual(orig);
    await s.remove();
    expect(await s.load()).toBeNull();
  });
});

describe("keyfile store", () => {
  const file = () => path.join(tmp, "root.key");

  test("round-trips a key", async () => {
    const s = openKeyfileStore(file(), "correct horse");
    expect(s.kind).toBe("keyfile");
    expect(await s.load()).toBeNull();
    const k = randomKey();
    await s.save(k);
    expect(await openKeyfileStore(file(), "correct horse").load()).toEqual(k);
  }, 30_000);

  test("wrong passphrase throws WrongPassphraseError", async () => {
    await openKeyfileStore(file(), "right").save(randomKey());
    const err = await openKeyfileStore(file(), "wrong")
      .load()
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(WrongPassphraseError);
    expect((err as Error).name).toBe("WrongPassphraseError");
  }, 30_000);

  test("file is {v:1,salt,sealed} JSON without the key in clear", async () => {
    const k = randomKey();
    await openKeyfileStore(file(), "pw").save(k);
    const raw = fs.readFileSync(file(), "utf8");
    const j = JSON.parse(raw) as Record<string, unknown>;
    expect(Object.keys(j).sort()).toEqual(["salt", "sealed", "v"]);
    expect(j.v).toBe(1);
    expect(raw).not.toContain(Buffer.from(k).toString("base64"));
    expect(raw).not.toContain(Buffer.from(k).toString("hex"));
  }, 30_000);

  test.skipIf(process.platform === "win32")(
    "file mode is 0600",
    async () => {
      await openKeyfileStore(file(), "pw").save(randomKey());
      expect(fs.statSync(file()).mode & 0o777).toBe(0o600);
    },
    30_000,
  );

  test("save leaves no temp files and replaces atomically", async () => {
    const s = openKeyfileStore(file(), "pw");
    const k1 = randomKey();
    const k2 = randomKey();
    await s.save(k1);
    await s.save(k2);
    expect(fs.readdirSync(tmp)).toEqual(["root.key"]);
    expect(await s.load()).toEqual(k2);
  }, 30_000);

  test("fresh salt per save", async () => {
    const s = openKeyfileStore(file(), "pw");
    const k = randomKey();
    await s.save(k);
    const a = JSON.parse(fs.readFileSync(file(), "utf8")).salt;
    await s.save(k);
    const b = JSON.parse(fs.readFileSync(file(), "utf8")).salt;
    expect(a).not.toBe(b);
  }, 30_000);

  test("remove deletes the file and tolerates a missing one", async () => {
    const s = openKeyfileStore(file(), "pw");
    await s.save(randomKey());
    await s.remove();
    expect(fs.existsSync(file())).toBe(false);
    await s.remove();
    expect(await s.load()).toBeNull();
  }, 30_000);

  describe("corrupt files give KeyfileCorruptError, not WrongPassphraseError", () => {
    const sealedOk = Buffer.alloc(64, 1).toString("base64");
    const saltOk = Buffer.alloc(16, 2).toString("base64");
    const cases: [string, string][] = [
      ["invalid JSON", "not json"],
      ["JSON null", "null"],
      ["JSON array", "[]"],
      ["wrong version", JSON.stringify({ v: 2, salt: saltOk, sealed: sealedOk })],
      ["missing salt", JSON.stringify({ v: 1, sealed: sealedOk })],
      ["missing sealed", JSON.stringify({ v: 1, salt: saltOk })],
      ["non-string fields", JSON.stringify({ v: 1, salt: 5, sealed: [] })],
      ["empty salt", JSON.stringify({ v: 1, salt: "", sealed: sealedOk })],
      ["one-byte salt", JSON.stringify({ v: 1, salt: "AA==", sealed: sealedOk })],
      [
        "15-byte salt",
        JSON.stringify({ v: 1, salt: Buffer.alloc(15).toString("base64"), sealed: sealedOk }),
      ],
      ["salt that is not base64", JSON.stringify({ v: 1, salt: "!!!!", sealed: sealedOk })],
      ["empty sealed", JSON.stringify({ v: 1, salt: saltOk, sealed: "" })],
      [
        "truncated sealed data",
        JSON.stringify({ v: 1, salt: saltOk, sealed: Buffer.alloc(39).toString("base64") }),
      ],
    ];

    test.each(cases)("%s", async (_name, content) => {
      fs.writeFileSync(file(), content);
      const err = await openKeyfileStore(file(), "pw")
        .load()
        .catch((e: unknown) => e);
      expect(err).toBeInstanceOf(KeyfileCorruptError);
      expect(err).not.toBeInstanceOf(WrongPassphraseError);
      expect((err as Error).name).toBe("KeyfileCorruptError");
    });

    test("a truncated real keyfile", async () => {
      await openKeyfileStore(file(), "pw").save(randomKey());
      const j = JSON.parse(fs.readFileSync(file(), "utf8"));
      const sealed = Buffer.from(j.sealed, "base64").subarray(0, 30);
      fs.writeFileSync(file(), JSON.stringify({ ...j, sealed: sealed.toString("base64") }));
      await expect(openKeyfileStore(file(), "pw").load()).rejects.toBeInstanceOf(
        KeyfileCorruptError,
      );
    }, 30_000);
  });

  test("a flipped ciphertext bit is indistinguishable from a wrong passphrase", async () => {
    await openKeyfileStore(file(), "pw").save(randomKey());
    const j = JSON.parse(fs.readFileSync(file(), "utf8"));
    const sealed = Buffer.from(j.sealed, "base64");
    sealed[sealed.length - 1] = (sealed[sealed.length - 1] ?? 0) ^ 1;
    fs.writeFileSync(file(), JSON.stringify({ ...j, sealed: sealed.toString("base64") }));
    await expect(openKeyfileStore(file(), "pw").load()).rejects.toBeInstanceOf(
      WrongPassphraseError,
    );
  }, 30_000);

  test("save creates a missing parent dir as private and tightens a loose one", async () => {
    const dir = path.join(tmp, "nested", "keys");
    await openKeyfileStore(path.join(dir, "root.key"), "pw").save(randomKey());
    expect(fs.existsSync(path.join(dir, "root.key"))).toBe(true);
    if (process.platform === "win32") return;
    expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
    fs.chmodSync(dir, 0o755);
    await openKeyfileStore(path.join(dir, "root.key"), "pw").save(randomKey());
    expect(fs.statSync(dir).mode & 0o777).toBe(0o700);
  }, 30_000);

  test("equivalent Unicode passphrases match (NFKC)", async () => {
    const k = randomKey();
    await openKeyfileStore(file(), "caf\u00e9").save(k);
    expect(await openKeyfileStore(file(), "cafe\u0301").load()).toEqual(k);
  }, 30_000);
});

describe("mapKeyringError", () => {
  const MSG = "No Secret Service found. Run: agent-vault init --keystore keyfile";

  test.each([
    "Couldn't access platform storage: Secret Service: unlock prompt was dismissed",
    "Platform failure: DBus error: Failed to connect to socket /nonexistent: No such file or directory",
    "Secret Service: no result found",
  ])("maps %s", (message) => {
    const mapped = mapKeyringError(new Error(message));
    expect(mapped).toBeInstanceOf(KeyringUnavailableError);
    expect((mapped as Error).message).toBe(MSG);
    expect((mapped as Error).name).toBe("KeyringUnavailableError");
  });

  test("keeps the original error as cause", () => {
    const original = new Error("Secret Service: no result found");
    expect((mapKeyringError(original) as Error).cause).toBe(original);
  });

  test("any other error comes back unchanged", () => {
    const e = new Error("Platform failure: something else");
    expect(mapKeyringError(e)).toBe(e);
    const s = "a string";
    expect(mapKeyringError(s)).toBe(s);
  });
});

describe("openOsKeyring load() validates the stored value", () => {
  // Entry is mocked so no real credential store is touched.
  const loadWith = async (stored: string | null) => {
    vi.resetModules();
    vi.doMock("@napi-rs/keyring", () => ({
      Entry: class {
        getPassword() {
          return stored;
        }
      },
    }));
    const m = await import("../src/keystore.js");
    return m.openOsKeyring("av-test-mock").load();
  };
  afterEach(() => {
    vi.doUnmock("@napi-rs/keyring");
    vi.resetModules();
  });

  test("a 32-byte value loads", async () => {
    const k = randomKey();
    expect(await loadWith(Buffer.from(k).toString("base64"))).toEqual(k);
  });

  test("a missing entry is null", async () => {
    expect(await loadWith(null)).toBeNull();
  });

  test.each([
    ["too short", Buffer.alloc(31, 7).toString("base64")],
    ["too long", Buffer.alloc(33, 7).toString("base64")],
    ["empty", ""],
  ])("%s: typed error, no value bytes in the message", async (_n, stored) => {
    const err = await loadWith(stored).catch((e: unknown) => e);
    expect(err).toBeInstanceOf((await import("../src/keystore.js")).KeyringValueInvalidError);
    expect((err as Error).name).toBe("KeyringValueInvalidError");
    expect((err as Error).message).not.toContain(stored || "\0");
  });

  test("non-base64 is rejected without echoing it", async () => {
    const err = await loadWith("s3cr3t-not-base64!!").catch((e: unknown) => e);
    expect((err as Error).name).toBe("KeyringValueInvalidError");
    expect((err as Error).message).not.toContain("s3cr3t");
  });
});

// Review Focus 4. Runs in a child process so the env reaches the native addon for certain, and so
// the bus address is fixed before libdbus starts. Unsetting DBUS_SESSION_BUS_ADDRESS is not enough
// (dbus-x11 autolaunch), so point it at a socket that does not exist. The child runs the TypeScript
// source through tsx, so this does not depend on a prior build of this package.
describe.skipIf(process.platform !== "linux")("Linux without a Secret Service", () => {
  test("openOsKeyring().load() throws KeyringUnavailableError, never falls back to keyutils", () => {
    const root = path.resolve(import.meta.dirname, "../../..");
    const entry = pathToFileURL(path.join(root, "packages/platform/src/index.ts")).href;
    const script = `
      import(${JSON.stringify(entry)}).then(async (m) => {
        try {
          await m.openOsKeyring("av-test-no-secret-service").load();
          console.log("NO-ERROR");
        } catch (e) {
          console.log(e.name + "|" + e.message);
        }
      });`;
    const out = execFileSync(
      process.execPath,
      ["--import", "tsx", "--input-type=module", "-e", script],
      {
        cwd: root, // --import resolves "tsx" from here
        env: { ...process.env, DBUS_SESSION_BUS_ADDRESS: "unix:path=/nonexistent" },
        encoding: "utf8",
      },
    ).trim();
    expect(out).toBe(
      "KeyringUnavailableError|No Secret Service found. Run: agent-vault init --keystore keyfile",
    );
  });
});

// Touches the real OS credential store. CI only; never run locally.
const realKeyring = process.env.CI === "true" && process.env.AGENT_VAULT_TEST_REAL_KEYRING === "1";
describe.skipIf(!realKeyring)("real OS keyring (CI only)", () => {
  test("save, load, overwrite, remove under a throwaway account", async () => {
    const store = openOsKeyring(`av-test-${process.pid}-${Date.now()}`);
    expect(store.kind).toBe("os-keyring");
    try {
      expect(await store.load()).toBeNull();
      const k = randomKey();
      await store.save(k);
      expect(await store.load()).toEqual(k);
      const k2 = randomKey();
      await store.save(k2);
      expect(await store.load()).toEqual(k2);
    } finally {
      await store.remove();
    }
    expect(await store.load()).toBeNull();
  });
});
