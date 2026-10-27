import { randomUUID } from "node:crypto";
import path from "node:path";
import { mac, macEqual } from "@agent-vault/crypto";
import { type Db, inTransactionSync } from "./db.js";
import {
  BundleExistsError,
  BundleNotFoundError,
  InvalidEnvNameError,
  InvalidExePathError,
  MetadataTamperError,
  SecretNotFoundError,
} from "./errors.js";
import { assertName, lengthPrefixed, type Vault, vaultInternals } from "./vault.js";

export type BundleInfo = { name: string; env: Record<string, string>; exes: string[] };

type BundleRow = { id: string; name: string; meta_mac: Uint8Array };

const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

const byCodeUnit = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * MAC over the bundle's id, name, every `env=secret` grant and every exe, each sorted. The counts
 * are part of the input so an entry cannot slide from one list to the other unnoticed.
 */
function bundleMac(
  macKey: Uint8Array,
  row: Pick<BundleRow, "id" | "name">,
  env: Record<string, string>,
  exes: string[],
): Uint8Array {
  const grants = Object.entries(env)
    .map(([k, s]) => `${k}=${s}`)
    .sort(byCodeUnit);
  const sortedExes = [...exes].sort(byCodeUnit);
  return mac(
    macKey,
    lengthPrefixed([
      "bundles",
      row.id,
      row.name,
      String(grants.length),
      ...grants,
      String(sortedExes.length),
      ...sortedExes,
    ]),
  );
}

function readBundleParts(db: Db, id: string): { env: Record<string, string>; exes: string[] } {
  const envRows = db
    .prepare("SELECT env_name, secret_name FROM bundle_env WHERE bundle_id = ?")
    .all<{ env_name: string; secret_name: string }>(id);
  const exeRows = db
    .prepare("SELECT exe_path FROM bundle_exes WHERE bundle_id = ?")
    .all<{ exe_path: string }>(id);
  const env: Record<string, string> = Object.create(null);
  for (const r of envRows.sort((a, b) => byCodeUnit(a.env_name, b.env_name))) {
    env[r.env_name] = r.secret_name;
  }
  return { env, exes: exeRows.map((r) => r.exe_path).sort(byCodeUnit) };
}

/** A bundle with its MAC verified. Throws MetadataTamperError. */
function loadVerified(db: Db, macKey: Uint8Array, row: BundleRow): BundleInfo {
  const { env, exes } = readBundleParts(db, row.id);
  if (!macEqual(bundleMac(macKey, row, env, exes), row.meta_mac)) {
    throw new MetadataTamperError(row.name, "bundle");
  }
  return { name: row.name, env: { ...env }, exes };
}

function findBundle(db: Db, name: string): BundleRow {
  const row = db
    .prepare("SELECT id, name, meta_mac FROM bundles WHERE name = ?")
    .get<BundleRow>(name);
  if (!row) throw new BundleNotFoundError(name);
  return row;
}

/** Re-MAC a bundle after a change. Verifies the stored state first, so tampering is never blessed. */
function mutate(v: Vault, bundle: string, change: (db: Db, row: BundleRow) => void): void {
  const { db, macKey } = vaultInternals(v);
  assertName(bundle);
  inTransactionSync(db, () => {
    const row = findBundle(db, bundle);
    loadVerified(db, macKey, row);
    change(db, row);
    const { env, exes } = readBundleParts(db, row.id);
    db.prepare("UPDATE bundles SET meta_mac = ? WHERE id = ?").run(
      bundleMac(macKey, row, env, exes),
      row.id,
    );
  });
}

/** Create an empty bundle. Throws InvalidNameError or BundleExistsError. */
export function createBundle(v: Vault, name: string): void {
  const { db, macKey } = vaultInternals(v);
  assertName(name);
  inTransactionSync(db, () => {
    if (db.prepare("SELECT 1 AS x FROM bundles WHERE name = ?").get(name)) {
      throw new BundleExistsError(name);
    }
    const row = { id: randomUUID(), name };
    db.prepare("INSERT INTO bundles (id, name, meta_mac) VALUES (?, ?, ?)").run(
      row.id,
      row.name,
      bundleMac(macKey, row, {}, []),
    );
  });
}

/** Map env var `env` to `secret` in the bundle, replacing any earlier mapping of that env name. */
export function grant(v: Vault, bundle: string, g: { env: string; secret: string }): void {
  vaultInternals(v);
  if (typeof g.env !== "string" || !ENV_NAME_RE.test(g.env)) {
    throw new InvalidEnvNameError(String(g.env));
  }
  if (!v.has(g.secret)) throw new SecretNotFoundError(g.secret);
  mutate(v, bundle, (db, row) => {
    db.prepare(
      `INSERT INTO bundle_env (bundle_id, env_name, secret_name) VALUES (?, ?, ?)
       ON CONFLICT(bundle_id, env_name) DO UPDATE SET secret_name = excluded.secret_name`,
    ).run(row.id, g.env, g.secret);
  });
}

/**
 * Allow an executable to receive the bundle. The path is stored as given; the runner resolves
 * symlinks (realpath) at launch.
 */
export function allowExe(v: Vault, bundle: string, absPath: string): void {
  vaultInternals(v);
  if (typeof absPath !== "string" || !path.isAbsolute(absPath)) {
    throw new InvalidExePathError();
  }
  mutate(v, bundle, (db, row) => {
    db.prepare("INSERT OR IGNORE INTO bundle_exes (bundle_id, exe_path) VALUES (?, ?)").run(
      row.id,
      absPath,
    );
  });
}

/** Env name -> secret name, and the allowed executables, after verifying the bundle's MAC. */
export function resolveBundle(
  v: Vault,
  name: string,
): { env: Record<string, string>; exes: string[] } {
  const { db, macKey } = vaultInternals(v);
  assertName(name);
  const { env, exes } = loadVerified(db, macKey, findBundle(db, name));
  return { env, exes };
}

/** Every bundle, sorted by name, each MAC-verified. */
export function listBundles(v: Vault): BundleInfo[] {
  const { db, macKey } = vaultInternals(v);
  return db
    .prepare("SELECT id, name, meta_mac FROM bundles ORDER BY name")
    .all<BundleRow>()
    .map((row) => loadVerified(db, macKey, row));
}
