#!/usr/bin/env node
// Spike S3 step 5: scrub a literal string from files (temp file + rename, mode preserved), binary-safe.
// SQLite files (*.sqlite, *.db, *-wal, *-shm) get a SAME-LENGTH replacement (padded with "_") so page layout/offsets stay valid.
// usage: node scrub.mjs <needle> <replacement> <file...>
import { readFileSync, renameSync, statSync, writeFileSync } from "node:fs";

const [needle, repl, ...files] = process.argv.slice(2);
const n = Buffer.from(needle);
const isSqlite = (f) => /\.(sqlite|db)(-wal|-shm)?$/.test(f);
for (const f of files) {
  const before = readFileSync(f);
  if (!before.includes(n)) continue;
  const r = Buffer.from(
    isSqlite(f) ? repl.padEnd(needle.length, "_").slice(0, needle.length) : repl,
  );
  const parts = [];
  let i = 0;
  for (let j = before.indexOf(n, i); j !== -1; j = before.indexOf(n, i)) {
    parts.push(before.subarray(i, j), r);
    i = j + n.length;
  }
  parts.push(before.subarray(i));
  const tmp = `${f}.scrub-${process.pid}.tmp`;
  writeFileSync(tmp, Buffer.concat(parts), { mode: statSync(f).mode & 0o777 });
  renameSync(tmp, f);
  console.log("scrubbed", f);
}
