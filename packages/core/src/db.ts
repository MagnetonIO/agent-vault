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
  const db = new DatabaseSync(file);
  try {
    db.exec("PRAGMA journal_mode = WAL");
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

/** Run `fn` in an immediate (write-locking) transaction; roll back if it throws or rejects. */
export async function inTransaction<T>(db: Db, fn: () => T | Promise<T>): Promise<T> {
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
