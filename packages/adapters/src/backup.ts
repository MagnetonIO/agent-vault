import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ensurePrivateDir } from "@agent-vault/platform";

/** Longest file name most file systems accept, minus room for the timestamp and a counter. */
const NAME_TAIL_MAX = 180;

/** `/Users/me/.claude.json` as one file name: separators and drive colons become `_`. */
function sanitizePath(abs: string): string {
  const flat = abs.replace(/[\\/:]+/g, "_");
  return flat.length > NAME_TAIL_MAX ? flat.slice(flat.length - NAME_TAIL_MAX) : flat;
}

/**
 * Copy `file` into `backupsDir` as `<ISO-ts>-<sanitized-abs-path>` (mode 0600) and return the
 * copy's path. The copy holds whatever the original held, plaintext secrets included.
 */
export function backupFile(file: string, backupsDir: string, now = new Date()): string {
  const abs = path.resolve(file);
  const data = fs.readFileSync(abs);
  ensurePrivateDir(backupsDir);
  // ':' is not allowed in Windows file names.
  const stamp = now.toISOString().replace(/:/g, "-");
  const base = `${stamp}-${sanitizePath(abs)}`;
  for (let n = 1; ; n++) {
    const dest = path.join(backupsDir, n === 1 ? base : `${base}.${n}`);
    try {
      fs.writeFileSync(dest, data, { mode: 0o600, flag: "wx" });
      return dest;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
    }
  }
}

/**
 * Replace the file's content: temp file beside it, then rename. The mode is kept, and a symlinked
 * file (a dotfiles manager's) is written through, not replaced by a regular file.
 */
export function writeFileAtomic(file: string, data: string): void {
  const target = fs.realpathSync(file);
  const { mode } = fs.statSync(target);
  const tmp = `${target}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  try {
    fs.writeFileSync(tmp, data, { mode: mode & 0o777, flag: "wx" });
    fs.chmodSync(tmp, mode & 0o777); // the umask may have narrowed it
    fs.renameSync(tmp, target);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}
