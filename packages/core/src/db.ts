import fs from "node:fs";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";

export type Statement = {
  run(...args: SQLInputValue[]): { changes: number | bigint; lastInsertRowid: number | bigint };
  // biome-ignore lint/suspicious/noExplicitAny: rows are shaped by each caller's SQL
  get<T = any>(...args: SQLInputValue[]): T | undefined;
  // biome-ignore lint/suspicious/noExplicitAny: rows are shaped by each caller's SQL
  all<T = any>(...args: SQLInputValue[]): T[];
};

export type Db = {
  exec(sql: string): void;
  prepare(sql: string): Statement;
  close(): void;
};

/** How long a connection waits for another connection's lock before "database is locked". */
const BUSY_TIMEOUT_MS = 5000;

const SQLITE_BUSY = 5;
const WAL_RETRY_MS = 10;

/**
 * Switching to WAL needs a lock that SQLite's busy timeout does not wait for, so two processes
 * opening a new db at once can see "database is locked". Retry until the same deadline. WAL is
 * persistent, so this only costs anything the first time.
 */
function enableWal(db: DatabaseSync): void {
  const deadline = Date.now() + BUSY_TIMEOUT_MS;
  for (;;) {
    try {
      db.exec("PRAGMA journal_mode = WAL");
      return;
    } catch (err) {
      if ((err as { errcode?: number }).errcode !== SQLITE_BUSY || Date.now() >= deadline)
        throw err;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, WAL_RETRY_MS);
    }
  }
}

/**
 * Open (creating if needed) the vault database. WAL for concurrent readers, `secure_delete` so
 * deleted ciphertext is overwritten, foreign keys on. The file is created 0600 before SQLite
 * touches it, so WAL and shm files inherit that mode. Callers make the parent dir private first.
 */
export function openDb(file: string): Db {
  if (process.platform !== "win32") {
    fs.closeSync(fs.openSync(file, "a", 0o600));
    fs.chmodSync(file, 0o600);
  }
  const db = new DatabaseSync(file, { timeout: BUSY_TIMEOUT_MS });
  try {
    enableWal(db);
    db.exec("PRAGMA secure_delete = ON");
    db.exec("PRAGMA foreign_keys = ON");
  } catch (err) {
    db.close();
    throw err;
  }
  return {
    exec: (sql) => db.exec(sql),
    prepare: (sql) => db.prepare(sql) as Statement,
    close: () => db.close(),
  };
}

/**
 * Run `fn` in an immediate (write-locking) transaction; roll back if it throws or rejects, or if
 * COMMIT fails. `undo` then runs (best effort) to reverse side effects `fn` made outside the db.
 */
export async function inTransaction<T>(
  db: Db,
  fn: () => T | Promise<T>,
  undo?: () => Promise<void>,
): Promise<T> {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = await fn();
    db.exec("COMMIT");
    return result;
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // Keep the original error; the connection is unusable if even ROLLBACK failed.
    }
    try {
      await undo?.();
    } catch {
      // Keep the original error.
    }
    throw err;
  }
}

/** Synchronous `inTransaction` for callers whose body never awaits. */
export function inTransactionSync<T>(db: Db, fn: () => T): T {
  db.exec("BEGIN IMMEDIATE");
  try {
    const result = fn();
    db.exec("COMMIT");
    return result;
  } catch (err) {
    try {
      db.exec("ROLLBACK");
    } catch {
      // Keep the original error.
    }
    throw err;
  }
}

/** Fold the WAL into the main file and truncate it, so freed secret bytes do not linger there. */
export function checkpointWal(db: Db): void {
  try {
    db.exec("PRAGMA wal_checkpoint(TRUNCATE)");
  } catch {
    // Best effort: a reader in another process can block it, and SQLite checkpoints later anyway.
  }
}
