import { inTransactionSync } from "./db.js";
import { type Vault, vaultInternals } from "./vault.js";

export type ScrubRow = { id: number; harness: string; file: string; secretName: string };

type Row = { id: number; harness: string; file: string; secret_name: string };

/**
 * Queue one row per (file, secret) for `harness`. A pair that is already queued is not added
 * again. Returns how many rows were added. Names and paths only, never values.
 */
export function enqueueScrub(
  v: Vault,
  harness: string,
  entries: { file: string; secretName: string }[],
): number {
  const { db } = vaultInternals(v);
  let added = 0;
  inTransactionSync(db, () => {
    const exists = db.prepare(
      "SELECT 1 AS x FROM scrub_queue WHERE harness = ? AND file = ? AND secret_name = ?",
    );
    const insert = db.prepare(
      "INSERT INTO scrub_queue (harness, file, secret_name, created_at) VALUES (?, ?, ?, ?)",
    );
    const now = new Date().toISOString();
    for (const { file, secretName } of entries) {
      if (exists.get(harness, file, secretName)) continue;
      insert.run(harness, file, secretName, now);
      added++;
    }
  });
  return added;
}

/** Every queued row for `harness`, oldest first. */
export function listScrubQueue(v: Vault, harness: string): ScrubRow[] {
  const { db } = vaultInternals(v);
  return db
    .prepare("SELECT id, harness, file, secret_name FROM scrub_queue WHERE harness = ? ORDER BY id")
    .all<Row>(harness)
    .map((r) => ({ id: r.id, harness: r.harness, file: r.file, secretName: r.secret_name }));
}

/** Remove the rows with these ids. Returns how many were removed. */
export function deleteScrubRows(v: Vault, ids: number[]): number {
  const { db } = vaultInternals(v);
  let removed = 0;
  inTransactionSync(db, () => {
    const del = db.prepare("DELETE FROM scrub_queue WHERE id = ?");
    for (const id of ids) removed += Number(del.run(id).changes);
  });
  return removed;
}
