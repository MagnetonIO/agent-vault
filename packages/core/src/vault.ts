import { randomUUID } from "node:crypto";
import fs from "node:fs";
import {
  DecryptError,
  deriveSubkey,
  encodeAad,
  keyFromRecoveryWords,
  mac,
  macEqual,
  open,
  randomKey,
  recoveryWords,
  seal,
} from "@agent-vault/crypto";
import { ensurePrivateDir, type RootKeyStore, type VaultPaths } from "@agent-vault/platform";
import { checkpointWal, type Db, inTransaction, inTransactionSync, openDb } from "./db.js";
import {
  InvalidNameError,
  MetadataTamperError,
  RecoveryFailedError,
  RootKeyMissingError,
  SecretNotFoundError,
  UnsupportedSchemaError,
  VaultClosedError,
  VaultExistsError,
  VaultNotInitializedError,
} from "./errors.js";
import { applySchema, SCHEMA_VERSION } from "./migrations.js";

export type SecretMeta = {
  name: string;
  type: string;
  length: number;
  tags: string[];
  createdAt: string;
  updatedAt: string;
};

type Locations = { paths: VaultPaths; store: RootKeyStore };

type MetaRow = {
  vault_id: string;
  schema_version: number;
  wrapped_dk_device: Uint8Array;
  wrapped_dk_recovery: Uint8Array;
};

type SecretRow = {
  id: string;
  name: string;
  type: string;
  ciphertext: Uint8Array;
  length: number;
  version: number;
  tags_json: string;
  created_at: string;
  updated_at: string;
  meta_mac: Uint8Array;
};

const NAME_RE = /^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*)*$/;
const NAME_MAX = 128;
const DEFAULT_TYPE = "generic";

function assertName(name: string): void {
  if (typeof name !== "string" || name.length > NAME_MAX || !NAME_RE.test(name)) {
    throw new InvalidNameError(String(name));
  }
}

function dkAad(vaultId: string, field: "dk_device" | "dk_recovery"): Uint8Array {
  return encodeAad({ vaultId, table: "meta", recordId: "vault", field, version: 1 });
}

function valueAad(vaultId: string, row: Pick<SecretRow, "id" | "version">): Uint8Array {
  return encodeAad({
    vaultId,
    table: "secrets",
    recordId: row.id,
    field: "value",
    version: row.version,
  });
}

/** Each part as u32 BE length + UTF-8 bytes, so no two field lists encode alike. */
function lengthPrefixed(parts: string[]): Uint8Array {
  const enc = new TextEncoder();
  const bytes = parts.map((p) => enc.encode(p));
  const out = new Uint8Array(bytes.reduce((n, b) => n + 4 + b.length, 0));
  const view = new DataView(out.buffer);
  let off = 0;
  for (const b of bytes) {
    view.setUint32(off, b.length);
    out.set(b, off + 4);
    off += 4 + b.length;
  }
  return out;
}

function secretMac(macKey: Uint8Array, r: Omit<SecretRow, "ciphertext" | "meta_mac">): Uint8Array {
  return mac(
    macKey,
    lengthPrefixed([
      "secrets",
      r.id,
      r.name,
      r.type,
      String(r.length),
      String(r.version),
      r.tags_json,
      r.created_at,
      r.updated_at,
    ]),
  );
}

const fileLocks = new Map<string, Promise<void>>();

/**
 * Run `fn` after every earlier call for the same file has finished. `initVault` and
 * `recoverVault` hold a SQLite write lock across an await; a second connection in this process
 * would block the thread waiting on it, so the event loop could never let the first finish.
 * Other processes wait on the busy timeout instead.
 */
async function serialized<T>(file: string, fn: () => Promise<T>): Promise<T> {
  const prev = fileLocks.get(file) ?? Promise.resolve();
  const run = prev.then(fn, fn);
  const tail = run.then(
    () => undefined,
    () => undefined,
  );
  fileLocks.set(file, tail);
  try {
    return await run;
  } finally {
    if (fileLocks.get(file) === tail) fileLocks.delete(file);
  }
}

function readMeta(db: Db): MetaRow | undefined {
  return db
    .prepare("SELECT vault_id, schema_version, wrapped_dk_device, wrapped_dk_recovery FROM meta")
    .get<MetaRow>();
}

/** Open the db for an existing vault: its file must exist and hold a meta row we understand. */
function openExisting(paths: VaultPaths): { db: Db; meta: MetaRow } {
  if (!fs.existsSync(paths.dbFile)) throw new VaultNotInitializedError();
  ensurePrivateDir(paths.dataDir);
  const db = openDb(paths.dbFile);
  try {
    applySchema(db);
    const meta = readMeta(db);
    if (!meta) throw new VaultNotInitializedError();
    if (meta.schema_version !== SCHEMA_VERSION) {
      throw new UnsupportedSchemaError(meta.schema_version);
    }
    return { db, meta };
  } catch (err) {
    db.close();
    throw err;
  }
}

/** The encrypted vault. Obtain one from `initVault`, `openVault` or `recoverVault`. */
export class Vault {
  readonly vaultId: string;
  #db: Db;
  #dk: Uint8Array;
  #macKey: Uint8Array;
  #closed = false;

  /** @internal Use `initVault`, `openVault` or `recoverVault`. Takes ownership of `dk`. */
  constructor(db: Db, vaultId: string, dk: Uint8Array) {
    this.#db = db;
    this.vaultId = vaultId;
    this.#dk = dk;
    this.#macKey = deriveSubkey(dk, "mac");
  }

  #assertOpen(): void {
    if (this.#closed) throw new VaultClosedError();
  }

  /** The row for `name` with its MAC verified, or undefined. Throws MetadataTamperError. */
  #verifiedRow(name: string): SecretRow | undefined {
    const row = this.#db.prepare("SELECT * FROM secrets WHERE name = ?").get<SecretRow>(name);
    if (row) this.#verify(row);
    return row;
  }

  #verify(row: SecretRow): void {
    if (!macEqual(secretMac(this.#macKey, row), row.meta_mac)) {
      throw new MetadataTamperError(row.name);
    }
  }

  #toMeta(row: SecretRow): SecretMeta {
    return {
      name: row.name,
      type: row.type,
      length: row.length,
      tags: JSON.parse(row.tags_json) as string[],
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }

  /**
   * Store `value` under `name`. An existing name is overwritten: the row keeps its id and
   * `createdAt`, the version goes up by one, and `type`/`tags` are kept unless given.
   */
  putSecret(
    name: string,
    value: Uint8Array,
    opts: { type?: string; tags?: string[] } = {},
  ): SecretMeta {
    this.#assertOpen();
    assertName(name);
    const { meta, overwrote } = inTransactionSync(this.#db, () => {
      const existing = this.#verifiedRow(name);
      const now = new Date().toISOString();
      const fields = {
        id: existing?.id ?? randomUUID(),
        name,
        type: opts.type ?? existing?.type ?? DEFAULT_TYPE,
        length: value.length,
        version: (existing?.version ?? 0) + 1,
        tags_json: JSON.stringify(opts.tags ?? (existing ? JSON.parse(existing.tags_json) : [])),
        created_at: existing?.created_at ?? now,
        updated_at: now,
      };
      const row: SecretRow = {
        ...fields,
        ciphertext: seal(this.#dk, value, valueAad(this.vaultId, fields)),
        meta_mac: secretMac(this.#macKey, fields),
      };
      this.#db
        .prepare(
          `INSERT INTO secrets (id, name, type, ciphertext, length, version, tags_json, created_at, updated_at, meta_mac)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET type = excluded.type, ciphertext = excluded.ciphertext,
             length = excluded.length, version = excluded.version, tags_json = excluded.tags_json,
             updated_at = excluded.updated_at, meta_mac = excluded.meta_mac`,
        )
        .run(
          row.id,
          row.name,
          row.type,
          row.ciphertext,
          row.length,
          row.version,
          row.tags_json,
          row.created_at,
          row.updated_at,
          row.meta_mac,
        );
      return { meta: this.#toMeta(row), overwrote: existing !== undefined };
    });
    // The old ciphertext sits in the WAL until it is checkpointed.
    if (overwrote) checkpointWal(this.#db);
    return meta;
  }

  /** Metadata for every secret, by name. Never a value. Throws MetadataTamperError. */
  list(): SecretMeta[] {
    this.#assertOpen();
    const rows = this.#db.prepare("SELECT * FROM secrets ORDER BY name").all<SecretRow>();
    return rows.map((row) => {
      this.#verify(row);
      return this.#toMeta(row);
    });
  }

  has(name: string): boolean {
    this.#assertOpen();
    assertName(name);
    return this.#verifiedRow(name) !== undefined;
  }

  /** True if a secret was deleted. */
  remove(name: string): boolean {
    this.#assertOpen();
    assertName(name);
    const removed = inTransactionSync(
      this.#db,
      () => Number(this.#db.prepare("DELETE FROM secrets WHERE name = ?").run(name).changes) > 0,
    );
    checkpointWal(this.#db);
    return removed;
  }

  addTag(name: string, tag: string): void {
    this.#assertOpen();
    assertName(name);
    if (typeof tag !== "string" || tag.length === 0) throw new TypeError("tag must be non-empty");
    inTransactionSync(this.#db, () => {
      const row = this.#verifiedRow(name);
      if (!row) throw new SecretNotFoundError(name);
      const tags = JSON.parse(row.tags_json) as string[];
      if (tags.includes(tag)) return;
      const next = {
        ...row,
        tags_json: JSON.stringify([...tags, tag]),
        updated_at: new Date().toISOString(),
      };
      this.#db
        .prepare("UPDATE secrets SET tags_json = ?, updated_at = ?, meta_mac = ? WHERE id = ?")
        .run(next.tags_json, next.updated_at, secretMac(this.#macKey, next), row.id);
    });
  }

  /**
   * Decrypt a secret. Internal: only the runner, helper and scrubber inside vaultd call this.
   * The caller owns the returned buffer and should zero it after use.
   */
  readValue(name: string): Uint8Array {
    this.#assertOpen();
    assertName(name);
    const row = this.#verifiedRow(name);
    if (!row) throw new SecretNotFoundError(name);
    return open(this.#dk, row.ciphertext, valueAad(this.vaultId, row));
  }

  /** Zero the in-memory keys and close the db. Safe to call twice; nothing else works after. */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#dk.fill(0);
    this.#macKey.fill(0);
    checkpointWal(this.#db);
    this.#db.close();
  }
}

/** Create a new vault. The 24 recovery words are returned once and stored nowhere. */
export function initVault(loc: Locations): Promise<{ vault: Vault; recoveryWords: string[] }> {
  return serialized(loc.paths.dbFile, () => initLocked(loc));
}

async function initLocked({
  paths,
  store,
}: Locations): Promise<{ vault: Vault; recoveryWords: string[] }> {
  ensurePrivateDir(paths.dataDir);
  const db = openDb(paths.dbFile);
  const dk = randomKey();
  const rk = randomKey();
  const rec = randomKey();
  try {
    applySchema(db);
    const vaultId = randomUUID();
    // The write lock is held across store.save: the root key is only replaced if this init is
    // the one that will commit, so a losing racer cannot overwrite the winner's key.
    await inTransaction(db, async () => {
      if (readMeta(db)) throw new VaultExistsError();
      db.prepare(
        "INSERT INTO meta (vault_id, schema_version, wrapped_dk_device, wrapped_dk_recovery) VALUES (?, ?, ?, ?)",
      ).run(
        vaultId,
        SCHEMA_VERSION,
        seal(rk, dk, dkAad(vaultId, "dk_device")),
        seal(rec, dk, dkAad(vaultId, "dk_recovery")),
      );
      await store.save(rk);
    });
    const words = recoveryWords(rec);
    return { vault: new Vault(db, vaultId, dk), recoveryWords: words };
  } catch (err) {
    dk.fill(0);
    db.close();
    throw err;
  } finally {
    rk.fill(0);
    rec.fill(0);
  }
}

/** Open an existing vault with the device root key from `store`. */
export async function openVault({ paths, store }: Locations): Promise<Vault> {
  const { db, meta } = openExisting(paths);
  let rk: Uint8Array | null = null;
  try {
    rk = await store.load();
    if (!rk) throw new RootKeyMissingError();
    let dk: Uint8Array;
    try {
      dk = open(rk, meta.wrapped_dk_device, dkAad(meta.vault_id, "dk_device"));
    } catch (err) {
      if (err instanceof DecryptError) throw new RootKeyMissingError(err);
      throw err;
    }
    return new Vault(db, meta.vault_id, dk);
  } catch (err) {
    db.close();
    throw err;
  } finally {
    rk?.fill(0);
  }
}

/**
 * Open a vault from the recovery words, on a device with no (or a stale) root key. A fresh root
 * key is made, saved to `store`, and the device wrap is replaced in one transaction. The recovery
 * wrap is untouched, so the same words keep working.
 */
export function recoverVault(loc: Locations & { words: string[] }): Promise<Vault> {
  return serialized(loc.paths.dbFile, () => recoverLocked(loc));
}

async function recoverLocked({
  paths,
  store,
  words,
}: Locations & { words: string[] }): Promise<Vault> {
  const { db, meta } = openExisting(paths);
  let rec: Uint8Array | null = null;
  let rk: Uint8Array | null = null;
  let dk: Uint8Array | null = null;
  try {
    try {
      rec = keyFromRecoveryWords(words);
      dk = open(rec, meta.wrapped_dk_recovery, dkAad(meta.vault_id, "dk_recovery"));
    } catch (err) {
      // Bad checksum, unknown word, wrong count, or a valid mnemonic for some other key.
      throw new RecoveryFailedError(err);
    }
    const newRk = randomKey();
    rk = newRk;
    const wrapped = seal(newRk, dk, dkAad(meta.vault_id, "dk_device"));
    // If saving the new key or committing fails, put the store back as it was: a half-written
    // keyring entry must not lock this device out of a vault whose db is unchanged.
    const old = await store.load();
    try {
      await inTransaction(
        db,
        async () => {
          db.prepare("UPDATE meta SET wrapped_dk_device = ? WHERE vault_id = ?").run(
            wrapped,
            meta.vault_id,
          );
          await store.save(newRk);
        },
        () => (old ? store.save(old) : store.remove()),
      );
    } finally {
      old?.fill(0);
    }
    return new Vault(db, meta.vault_id, dk);
  } catch (err) {
    dk?.fill(0);
    db.close();
    throw err;
  } finally {
    rec?.fill(0);
    rk?.fill(0);
  }
}
