import type { Db } from "./db.js";

export const SCHEMA_VERSION = 1;

/**
 * Schema v1. `meta` holds exactly one row (the constant unique index). Bundles and the audit log
 * are filled in by later tasks; their tables exist from the start so v1 is one schema.
 */
const V1 = `
CREATE TABLE IF NOT EXISTS meta (
  vault_id TEXT NOT NULL,
  schema_version INTEGER NOT NULL,
  wrapped_dk_device BLOB NOT NULL,
  wrapped_dk_recovery BLOB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS meta_single_row ON meta ((1));

CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  type TEXT NOT NULL,
  ciphertext BLOB NOT NULL,
  length INTEGER NOT NULL,
  version INTEGER NOT NULL,
  tags_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  meta_mac BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS bundles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  meta_mac BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS bundle_env (
  bundle_id TEXT NOT NULL REFERENCES bundles(id) ON DELETE CASCADE,
  env_name TEXT NOT NULL,
  secret_name TEXT NOT NULL,
  PRIMARY KEY (bundle_id, env_name)
);
CREATE TABLE IF NOT EXISTS bundle_exes (
  bundle_id TEXT NOT NULL REFERENCES bundles(id) ON DELETE CASCADE,
  exe_path TEXT NOT NULL,
  PRIMARY KEY (bundle_id, exe_path)
);

CREATE TABLE IF NOT EXISTS audit_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  event_json TEXT NOT NULL,
  prev_hmac BLOB NOT NULL,
  hmac BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS scrub_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  harness TEXT NOT NULL,
  file TEXT NOT NULL,
  secret_name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
`;

/** Create every v1 table. Idempotent; the version itself lives in the `meta` row. */
export function applySchema(db: Db): void {
  db.exec(V1);
}
