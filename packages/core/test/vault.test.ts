import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DecryptError, randomKey, recoveryWords } from "@agent-vault/crypto";
import {
  getPaths,
  KeyfileCorruptError,
  KeyringValueInvalidError,
  MemoryKeyStore,
  type VaultPaths,
  WrongPassphraseError,
} from "@agent-vault/platform";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import {
  InvalidNameError,
  initVault,
  MetadataTamperError,
  openDb,
  openVault,
  RecoveryFailedError,
  RootKeyMissingError,
  recoverVault,
  SecretNotFoundError,
  VaultClosedError,
  VaultExistsError,
  VaultNotInitializedError,
} from "../src/index.js";

const posix = process.platform !== "win32";
const enc = new TextEncoder();
const dec = new TextDecoder();

let tmp: string;
let paths: VaultPaths;
let store: MemoryKeyStore;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "av-core-"));
  paths = getPaths({ AGENT_VAULT_HOME: path.join(tmp, "vault") }, process.platform);
  store = new MemoryKeyStore();
});

afterEach(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** Run raw SQL against the vault file, as an attacker with disk access would. */
function withRawDb<T>(fn: (db: ReturnType<typeof openDb>) => T): T {
  const db = openDb(paths.dbFile);
  try {
    return fn(db);
  } finally {
    db.close();
  }
}

describe("round trip", () => {
  test("init, put, close, open, readValue", async () => {
    const { vault, recoveryWords: words } = await initVault({ paths, store });
    expect(words).toHaveLength(24);
    vault.putSecret("github/token", enc.encode("ghp_supersecret"), { type: "api-key" });
    vault.close();

    const reopened = await openVault({ paths, store });
    expect(dec.decode(reopened.readValue("github/token"))).toBe("ghp_supersecret");
    reopened.close();
  });

  test("list returns metadata only and never a value", async () => {
    const { vault } = await initVault({ paths, store });
    const meta = vault.putSecret("db.password", enc.encode("hunter2-hunter2"), { tags: ["prod"] });
    expect(meta).toMatchObject({
      name: "db.password",
      type: "generic",
      length: 15,
      tags: ["prod"],
    });
    expect(meta.createdAt).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);

    const rows = vault.list();
    expect(rows).toEqual([meta]);
    expect(Object.keys(rows[0] ?? {}).sort()).toEqual(
      ["createdAt", "length", "name", "tags", "type", "updatedAt"].sort(),
    );
    expect(JSON.stringify(rows)).not.toContain("hunter2");
    vault.close();
  });

  test("length is the byte length, not the character count", async () => {
    const { vault } = await initVault({ paths, store });
    expect(vault.putSecret("utf8", enc.encode("héllo✓")).length).toBe(enc.encode("héllo✓").length);
    vault.close();
  });

  test("list is ordered by name", async () => {
    const { vault } = await initVault({ paths, store });
    for (const n of ["b", "a/z", "a"]) vault.putSecret(n, enc.encode("v"));
    expect(vault.list().map((m) => m.name)).toEqual(["a", "a/z", "b"]);
    vault.close();
  });

  test("the plaintext never reaches the db or wal file", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("leak.check", enc.encode("PLAINTEXT-CANARY-9f3a"));
    const scan = () =>
      [paths.dbFile, `${paths.dbFile}-wal`]
        .filter((f) => fs.existsSync(f))
        .some((f) => fs.readFileSync(f).includes("PLAINTEXT-CANARY-9f3a"));
    expect(scan()).toBe(false);
    vault.close();
    expect(scan()).toBe(false);
  });
});

describe("tamper detection", () => {
  test("flipping one ciphertext byte makes readValue throw", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("value-a"));
    withRawDb((db) => {
      const row = db.prepare("SELECT ciphertext FROM secrets WHERE name = ?").get("a");
      const ct = Uint8Array.from(row.ciphertext as Uint8Array);
      ct[ct.length - 1] = (ct[ct.length - 1] ?? 0) ^ 1;
      db.prepare("UPDATE secrets SET ciphertext = ? WHERE name = ?").run(ct, "a");
    });
    expect(() => vault.readValue("a")).toThrow(DecryptError);
    vault.close();
  });

  test("swapping the ciphertext of two rows makes both throw", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("value-a"));
    vault.putSecret("b", enc.encode("value-b"));
    withRawDb((db) => {
      const get = (n: string) =>
        db.prepare("SELECT ciphertext FROM secrets WHERE name = ?").get(n).ciphertext as Uint8Array;
      const [ca, cb] = [get("a"), get("b")];
      db.prepare("UPDATE secrets SET ciphertext = ? WHERE name = ?").run(cb, "a");
      db.prepare("UPDATE secrets SET ciphertext = ? WHERE name = ?").run(ca, "b");
    });
    expect(() => vault.readValue("a")).toThrow(DecryptError);
    expect(() => vault.readValue("b")).toThrow(DecryptError);
    vault.close();
  });

  test("editing tags_json in SQL makes list throw MetadataTamperError", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("v"), { tags: ["dev"] });
    withRawDb((db) =>
      db.prepare("UPDATE secrets SET tags_json = ? WHERE name = ?").run('["prod"]', "a"),
    );
    expect(() => vault.list()).toThrow(MetadataTamperError);
    try {
      vault.list();
    } catch (e) {
      expect((e as MetadataTamperError).message).toContain("a");
    }
    vault.close();
  });

  test.each([
    ["type", "'other'"],
    ["length", "3"],
    ["version", "9"],
    ["created_at", "'2000-01-01T00:00:00.000Z'"],
    ["updated_at", "'2000-01-01T00:00:00.000Z'"],
    ["name", "'renamed'"],
  ])("editing %s is detected by has, list and readValue", async (column, sqlValue) => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("value"));
    withRawDb((db) => db.exec(`UPDATE secrets SET ${column} = ${sqlValue}`));
    const name = column === "name" ? "renamed" : "a";
    expect(() => vault.has(name)).toThrow(MetadataTamperError);
    expect(() => vault.list()).toThrow(MetadataTamperError);
    expect(() => vault.readValue(name)).toThrow(MetadataTamperError);
    vault.close();
  });

  test("addTag and overwrite refuse a tampered row instead of re-MACing it", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("v"));
    withRawDb((db) => db.prepare("UPDATE secrets SET tags_json = ?").run('["evil"]'));
    expect(() => vault.addTag("a", "ok")).toThrow(MetadataTamperError);
    expect(() => vault.putSecret("a", enc.encode("w"))).toThrow(MetadataTamperError);
    expect(() => vault.list()).toThrow(MetadataTamperError);
    vault.close();
  });
});

describe("overwrite, remove, tags", () => {
  test("overwrite bumps version, keeps id and createdAt, and the old ciphertext is unreadable", async () => {
    const { vault } = await initVault({ paths, store });
    const first = vault.putSecret("a", enc.encode("old"));
    const before = withRawDb((db) =>
      db.prepare("SELECT id, version, ciphertext FROM secrets WHERE name = ?").get("a"),
    );
    expect(before.version).toBe(1);

    const second = vault.putSecret("a", enc.encode("new-value"));
    expect(second.createdAt).toBe(first.createdAt);
    expect(second.updatedAt >= first.updatedAt).toBe(true);
    expect(second.length).toBe(9);
    expect(vault.list()).toHaveLength(1);

    const after = withRawDb((db) =>
      db.prepare("SELECT id, version FROM secrets WHERE name = ?").get("a"),
    );
    expect(after).toMatchObject({ id: before.id, version: 2 });
    expect(dec.decode(vault.readValue("a"))).toBe("new-value");

    // Roll the stored ciphertext back to the version-1 bytes: the AAD version no longer matches.
    withRawDb((db) =>
      db.prepare("UPDATE secrets SET ciphertext = ? WHERE name = ?").run(before.ciphertext, "a"),
    );
    expect(() => vault.readValue("a")).toThrow(DecryptError);
    vault.close();
  });

  test("overwrite without options keeps the existing type and tags", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("v1"), { type: "api-key", tags: ["x"] });
    const m = vault.putSecret("a", enc.encode("v2"));
    expect(m).toMatchObject({ type: "api-key", tags: ["x"] });
    vault.close();
  });

  test("remove deletes the row and reports whether it existed", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("v"));
    expect(vault.remove("a")).toBe(true);
    expect(vault.has("a")).toBe(false);
    expect(vault.remove("a")).toBe(false);
    expect(vault.remove("never-existed")).toBe(false);
    expect(() => vault.readValue("a")).toThrow(SecretNotFoundError);
    vault.close();
  });

  test("addTag adds once, keeps the secret readable, and rejects unknown names", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("v"));
    vault.addTag("a", "prod");
    vault.addTag("a", "prod");
    vault.addTag("a", "db");
    expect(vault.list()[0]?.tags).toEqual(["prod", "db"]);
    expect(dec.decode(vault.readValue("a"))).toBe("v");
    expect(() => vault.addTag("missing", "x")).toThrow(SecretNotFoundError);
    vault.close();
  });

  test("readValue on a missing name throws SecretNotFoundError", async () => {
    const { vault } = await initVault({ paths, store });
    expect(() => vault.readValue("nope")).toThrow(SecretNotFoundError);
    vault.close();
  });
});

describe("names", () => {
  test.each([
    ["../x"],
    ["A"],
    ["a".repeat(129)],
    [""],
    ["/a"],
    ["a/"],
    ["a//b"],
    ["-a"],
    ["a b"],
    ["a\nb"],
  ])("rejects %j", async (bad) => {
    const { vault } = await initVault({ paths, store });
    expect(() => vault.putSecret(bad, enc.encode("v"))).toThrow(InvalidNameError);
    expect(() => vault.has(bad)).toThrow(InvalidNameError);
    expect(() => vault.readValue(bad)).toThrow(InvalidNameError);
    expect(() => vault.remove(bad)).toThrow(InvalidNameError);
    vault.close();
  });

  test("accepts the longest legal name and nested names", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a".repeat(128), enc.encode("v"));
    vault.putSecret("aws/prod.key_1-x", enc.encode("v"));
    expect(vault.list()).toHaveLength(2);
    vault.close();
  });

  test("the error message carries nothing but the name", () => {
    expect(new InvalidNameError("Bad Name").message).toBe('invalid secret name: "Bad Name"');
  });
});

describe("init and open errors", () => {
  test("init twice throws VaultExistsError and leaves the first vault openable", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("v"));
    vault.close();

    const other = new MemoryKeyStore();
    await expect(initVault({ paths, store: other })).rejects.toThrow(VaultExistsError);
    expect(await other.load()).toBeNull();

    const again = await openVault({ paths, store });
    expect(dec.decode(again.readValue("a"))).toBe("v");
    again.close();
  });

  test("openVault before init throws VaultNotInitializedError and creates no db", async () => {
    await expect(openVault({ paths, store })).rejects.toThrow(VaultNotInitializedError);
    expect(fs.existsSync(paths.dbFile)).toBe(false);
  });

  test("openVault on a db without a meta row throws VaultNotInitializedError", async () => {
    fs.mkdirSync(paths.dataDir, { recursive: true });
    openDb(paths.dbFile).close();
    await expect(openVault({ paths, store })).rejects.toThrow(VaultNotInitializedError);
  });

  test("openVault with an empty key store throws RootKeyMissingError", async () => {
    const { vault } = await initVault({ paths, store });
    vault.close();
    await expect(openVault({ paths, store: new MemoryKeyStore() })).rejects.toThrow(
      RootKeyMissingError,
    );
  });

  test("openVault with a wrong root key throws RootKeyMissingError caused by DecryptError", async () => {
    const { vault } = await initVault({ paths, store });
    vault.close();
    const wrong = new MemoryKeyStore();
    await wrong.save(randomKey());
    const err = await openVault({ paths, store: wrong }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(RootKeyMissingError);
    expect((err as RootKeyMissingError).cause).toBeInstanceOf(DecryptError);
  });
});

describe("recovery", () => {
  test("a new store plus the words reads the secret and replaces the root key", async () => {
    const { vault, recoveryWords: words } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("survives"));
    vault.close();

    const storeB = new MemoryKeyStore();
    const recovered = await recoverVault({ paths, store: storeB, words });
    expect(dec.decode(recovered.readValue("a"))).toBe("survives");
    recovered.close();

    expect(await storeB.load()).not.toBeNull();
    const viaB = await openVault({ paths, store: storeB });
    expect(dec.decode(viaB.readValue("a"))).toBe("survives");
    viaB.close();

    // The old device key no longer unwraps anything.
    await expect(openVault({ paths, store })).rejects.toThrow(RootKeyMissingError);
  });

  test("the same words still work after a recovery", async () => {
    const { vault, recoveryWords: words } = await initVault({ paths, store });
    vault.close();
    (await recoverVault({ paths, store: new MemoryKeyStore(), words })).close();
    (await recoverVault({ paths, store: new MemoryKeyStore(), words })).close();
  });

  test("wrong words throw RecoveryFailedError and change nothing", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("v"));
    vault.close();

    const storeB = new MemoryKeyStore();
    const valid = recoveryWords(randomKey());
    const bad = [...valid.slice(0, 23), "abandon"];
    for (const words of [valid, bad, valid.slice(0, 12), ["notaword", ...valid.slice(1)]]) {
      await expect(recoverVault({ paths, store: storeB, words })).rejects.toThrow(
        RecoveryFailedError,
      );
    }
    expect(await storeB.load()).toBeNull();

    const still = await openVault({ paths, store });
    expect(dec.decode(still.readValue("a"))).toBe("v");
    still.close();
  });

  test("recoverVault before init throws VaultNotInitializedError", async () => {
    await expect(recoverVault({ paths, store, words: recoveryWords(randomKey()) })).rejects.toThrow(
      VaultNotInitializedError,
    );
  });

  test("RecoveryFailedError does not echo the words", async () => {
    const { vault } = await initVault({ paths, store });
    vault.close();
    const words = recoveryWords(randomKey());
    const err = await recoverVault({ paths, store: new MemoryKeyStore(), words }).catch(
      (e: unknown) => e,
    );
    // Not a single word: BIP39 has "valid" and "vault", which the message itself contains.
    const message = (err as Error).message;
    expect(message).not.toContain(words.join(" "));
    for (let i = 0; i + 3 <= words.length; i++) {
      expect(message).not.toContain(words.slice(i, i + 3).join(" "));
    }
  });
});

describe("close", () => {
  test("every method throws VaultClosedError afterwards", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("v"));
    vault.close();
    expect(() => vault.putSecret("b", enc.encode("v"))).toThrow(VaultClosedError);
    expect(() => vault.list()).toThrow(VaultClosedError);
    expect(() => vault.has("a")).toThrow(VaultClosedError);
    expect(() => vault.remove("a")).toThrow(VaultClosedError);
    expect(() => vault.addTag("a", "t")).toThrow(VaultClosedError);
    expect(() => vault.readValue("a")).toThrow(VaultClosedError);
  });

  test("close is idempotent", async () => {
    const { vault } = await initVault({ paths, store });
    vault.close();
    expect(() => vault.close()).not.toThrow();
  });
});

describe("storage hygiene", () => {
  test("the db is opened with WAL, secure_delete and foreign keys on", async () => {
    const { vault } = await initVault({ paths, store });
    withRawDb((db) => {
      expect(db.prepare("PRAGMA journal_mode").get().journal_mode).toBe("wal");
      expect(db.prepare("PRAGMA secure_delete").get().secure_delete).toBe(1);
      expect(db.prepare("PRAGMA foreign_keys").get().foreign_keys).toBe(1);
    });
    vault.close();
  });

  test("meta holds one row at schema version 1 and every v1 table exists", async () => {
    const { vault } = await initVault({ paths, store });
    withRawDb((db) => {
      const tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .all()
        .map((r) => r.name);
      for (const t of [
        "audit_log",
        "bundle_env",
        "bundle_exes",
        "bundles",
        "meta",
        "scrub_queue",
        "secrets",
      ]) {
        expect(tables).toContain(t);
      }
      const metas = db.prepare("SELECT * FROM meta").all();
      expect(metas).toHaveLength(1);
      expect(metas[0]?.schema_version).toBe(1);
      expect(metas[0]?.vault_id).toBe(vault.vaultId);
      expect(() =>
        db.exec(
          "INSERT INTO meta (vault_id, schema_version, wrapped_dk_device, wrapped_dk_recovery) VALUES ('x', 1, x'00', x'00')",
        ),
      ).toThrow();
    });
    vault.close();
  });

  test.skipIf(!posix)("the db file is 0600 and its directory 0700", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("v"));
    expect(fs.statSync(paths.dbFile).mode & 0o777).toBe(0o600);
    expect(fs.statSync(paths.dataDir).mode & 0o777).toBe(0o700);
    for (const side of [`${paths.dbFile}-wal`, `${paths.dbFile}-shm`]) {
      if (fs.existsSync(side)) expect(fs.statSync(side).mode & 0o077).toBe(0);
    }
    vault.close();
  });
});

/** A store whose `save` writes the key and then throws, like a keyring that fails mid-write. */
class WriteThenThrowStore extends MemoryKeyStore {
  failSaves = false;
  override async save(k: Uint8Array): Promise<void> {
    await super.save(k);
    if (this.failSaves) throw new Error("keyring write failed");
  }
}

describe("recovery rollback", () => {
  test("a failing save restores the old root key and leaves the vault openable", async () => {
    const flaky = new WriteThenThrowStore();
    const { vault, recoveryWords: words } = await initVault({ paths, store: flaky });
    vault.putSecret("a", enc.encode("kept"));
    vault.close();
    const oldKey = await flaky.load();

    flaky.failSaves = true;
    await expect(recoverVault({ paths, store: flaky, words })).rejects.toThrow(
      "keyring write failed",
    );
    flaky.failSaves = false;

    expect(await flaky.load()).toEqual(oldKey);
    const reopened = await openVault({ paths, store: flaky });
    expect(dec.decode(reopened.readValue("a"))).toBe("kept");
    reopened.close();
  });

  test("a failing save on a store that had no key leaves it empty", async () => {
    const { vault, recoveryWords: words } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("kept"));
    vault.close();

    const empty = new WriteThenThrowStore();
    empty.failSaves = true;
    await expect(recoverVault({ paths, store: empty, words })).rejects.toThrow(
      "keyring write failed",
    );
    expect(await empty.load()).toBeNull();

    const reopened = await openVault({ paths, store });
    expect(dec.decode(reopened.readValue("a"))).toBe("kept");
    reopened.close();
  });
});

/** A store whose entry cannot be read: the situation recovery exists for. */
class UnreadableStore extends MemoryKeyStore {
  unreadable = true;
  constructor(private readonly failure: () => Error) {
    super();
  }
  override async load(): Promise<Uint8Array | null> {
    if (this.unreadable) throw this.failure();
    return super.load();
  }
}

describe("recovery onto an unreadable key store", () => {
  test.each([
    ["WrongPassphraseError", () => new WrongPassphraseError()],
    ["KeyfileCorruptError", () => new KeyfileCorruptError("bad header")],
    ["KeyringValueInvalidError", () => new KeyringValueInvalidError("wrong length")],
  ])("succeeds when load() throws %s and the vault opens with the new key", async (_n, failure) => {
    const { vault, recoveryWords: words } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("kept"));
    vault.close();

    const broken = new UnreadableStore(failure);
    const recovered = await recoverVault({ paths, store: broken, words });
    expect(dec.decode(recovered.readValue("a"))).toBe("kept");
    recovered.close();

    broken.unreadable = false;
    const reopened = await openVault({ paths, store: broken });
    expect(dec.decode(reopened.readValue("a"))).toBe("kept");
    reopened.close();
  });

  test("a failing save does not call remove() when the old key was unreadable", async () => {
    const { vault, recoveryWords: words } = await initVault({ paths, store });
    vault.close();
    class Failing extends UnreadableStore {
      removed = false;
      override async save(): Promise<void> {
        throw new Error("keyring write failed");
      }
      override async remove(): Promise<void> {
        this.removed = true;
      }
    }
    const broken = new Failing(() => new KeyfileCorruptError("bad header"));
    await expect(recoverVault({ paths, store: broken, words })).rejects.toThrow(
      "keyring write failed",
    );
    expect(broken.removed).toBe(false);
  });
});

describe("concurrent access", () => {
  test("a write waits for another connection's lock instead of failing", async () => {
    const { vault } = await initVault({ paths, store });
    // node:sqlite blocks the thread while it waits, so the lock holder must be another process.
    const holder = spawn(
      process.execPath,
      [
        "-e",
        `const { DatabaseSync } = require("node:sqlite");
         const db = new DatabaseSync(process.argv[1]);
         db.exec("BEGIN IMMEDIATE");
         console.log("locked");
         setTimeout(() => { db.exec("ROLLBACK"); process.exit(0); }, 200);`,
        paths.dbFile,
      ],
      { stdio: ["ignore", "pipe", "inherit"] },
    );
    const exited = new Promise<void>((resolve) => holder.on("exit", () => resolve()));
    await new Promise<void>((resolve, reject) => {
      holder.on("error", reject);
      holder.stdout.once("data", () => resolve());
    });

    const started = Date.now();
    expect(() => vault.putSecret("a", enc.encode("v"))).not.toThrow();
    expect(Date.now() - started).toBeGreaterThanOrEqual(100);
    await exited;
    expect(dec.decode(vault.readValue("a"))).toBe("v");
    vault.close();
  });

  test("two racing inits give one vault and one VaultExistsError", async () => {
    const [s1, s2] = [new MemoryKeyStore(), new MemoryKeyStore()];
    const results = await Promise.allSettled([
      initVault({ paths, store: s1 }),
      initVault({ paths, store: s2 }),
    ]);
    const won = results.filter((r) => r.status === "fulfilled");
    const lost = results.filter((r) => r.status === "rejected");
    expect(won).toHaveLength(1);
    expect(lost).toHaveLength(1);
    expect((lost[0] as PromiseRejectedResult).reason).toBeInstanceOf(VaultExistsError);
    (won[0] as PromiseFulfilledResult<{ vault: { close(): void } }>).value.vault.close();

    // Exactly the winner's store holds a key, and it opens the vault.
    const keys = [await s1.load(), await s2.load()];
    expect(keys.filter((k) => k !== null)).toHaveLength(1);
    const winner = keys[0] ? s1 : s2;
    (await openVault({ paths, store: winner })).close();
  });
});

describe("WAL checkpoint does not stall", () => {
  test("remove and close return promptly while another connection holds a read transaction", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("v"));
    const reader = openDb(paths.dbFile);
    reader.exec("BEGIN");
    reader.prepare("SELECT count(*) FROM secrets").get();

    let started = Date.now();
    expect(vault.remove("a")).toBe(true);
    expect(Date.now() - started).toBeLessThan(500);

    vault.putSecret("b", enc.encode("v"));
    started = Date.now();
    vault.close();
    expect(Date.now() - started).toBeLessThan(500);
    reader.exec("ROLLBACK");
    reader.close();
  });

  test("the busy timeout is back to 5000 ms after a checkpoint", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("v"));
    vault.remove("a");
    // A write must still wait for another process's lock afterwards (see the lock test above).
    const holder = spawn(
      process.execPath,
      [
        "-e",
        `const { DatabaseSync } = require("node:sqlite");
         const db = new DatabaseSync(process.argv[1]);
         db.exec("BEGIN IMMEDIATE");
         console.log("locked");
         setTimeout(() => { db.exec("ROLLBACK"); process.exit(0); }, 200);`,
        paths.dbFile,
      ],
      { stdio: ["ignore", "pipe", "inherit"] },
    );
    const exited = new Promise<void>((resolve) => holder.on("exit", () => resolve()));
    await new Promise<void>((resolve) => holder.stdout.once("data", () => resolve()));
    expect(() => vault.putSecret("b", enc.encode("v"))).not.toThrow();
    await exited;
    vault.close();
  });
});

describe("WAL residue", () => {
  const walBytes = () =>
    fs.existsSync(`${paths.dbFile}-wal`) ? fs.readFileSync(`${paths.dbFile}-wal`) : Buffer.alloc(0);
  const ciphertextOf = (name: string): Buffer =>
    Buffer.from(
      withRawDb(
        (db) =>
          db.prepare("SELECT ciphertext FROM secrets WHERE name = ?").get(name)
            .ciphertext as Uint8Array,
      ),
    );
  // Any 32 bytes of a random ciphertext identify the row.
  const needle = (ct: Buffer) => ct.subarray(0, 32);

  test("remove leaves no copy of the ciphertext in the wal or the db", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("value-to-delete"));
    const gone = needle(ciphertextOf("a"));
    expect(walBytes().includes(gone)).toBe(true); // the wal does hold it before remove
    vault.remove("a");
    expect(walBytes().includes(gone)).toBe(false);
    expect(fs.readFileSync(paths.dbFile).includes(gone)).toBe(false);
    vault.close();
  });

  test("overwrite leaves no copy of the old ciphertext in the wal or the db", async () => {
    const { vault } = await initVault({ paths, store });
    vault.putSecret("a", enc.encode("old-value"));
    const old = needle(ciphertextOf("a"));
    vault.putSecret("a", enc.encode("new-value"));
    expect(walBytes().includes(old)).toBe(false);
    expect(fs.readFileSync(paths.dbFile).includes(old)).toBe(false);
    vault.close();
  });
});
