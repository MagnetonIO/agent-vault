import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ensurePrivateDir } from "@agent-vault/platform";
import { DaemonAlreadyRunningError } from "./errors.js";

/** An empty or unparseable lock this old is a crashed starter's, not one mid-write. */
const STALE_UNPARSEABLE_MS = 5000;

/** EPERM means the process exists but belongs to someone else: still alive. */
function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** Create the lock file holding our pid. False if it already exists. */
function tryCreate(file: string): boolean {
  let fd: number;
  try {
    fd = fs.openSync(file, "wx", 0o600);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw err;
  }
  try {
    fs.writeSync(fd, String(process.pid));
  } catch (err) {
    fs.closeSync(fd);
    fs.rmSync(file, { force: true });
    throw err;
  }
  fs.closeSync(fd);
  return true;
}

/**
 * Remove `file` if its holder is gone. True if the way is clear (removed, or already vanished).
 * The file is renamed aside first, so of several racing reapers only one takes it, and a lock a
 * new holder created in the meantime is put back instead of deleted.
 */
function reapStale(file: string): boolean {
  let text: string;
  let mtimeMs: number;
  try {
    text = fs.readFileSync(file, "utf8");
    mtimeMs = fs.statSync(file).mtimeMs;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return true;
    throw err;
  }
  const trimmed = text.trim();
  const pid = /^\d+$/.test(trimmed) ? Number(trimmed) : 0;
  const stale = pid > 0 ? !isAlive(pid) : Date.now() - mtimeMs > STALE_UNPARSEABLE_MS;
  if (!stale) return false;

  const aside = `${file}.stale.${process.pid}.${randomBytes(4).toString("hex")}`;
  try {
    fs.renameSync(file, aside);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return true;
    throw err;
  }
  const taken = fs.readFileSync(aside, "utf8");
  if (taken !== text) {
    try {
      fs.linkSync(aside, file); // fails if yet another holder has taken the slot; then theirs stands
    } catch {
      // nothing to restore
    }
    fs.rmSync(aside, { force: true });
    return false;
  }
  fs.rmSync(aside, { force: true });
  return true;
}

/**
 * Take the single-instance lock `<runtimeDir>/vaultd.lock`, holding this process's pid. Synchronous,
 * so concurrent starters (even in one process) are strictly ordered. Throws
 * DaemonAlreadyRunningError if a live process holds it. Returns the release function, which only
 * removes the file while it still holds our pid.
 *
 * A pid that the OS has reused for an unrelated live process keeps a stale lock alive; delete
 * `vaultd.lock` by hand in that case.
 */
export function acquireLock(runtimeDir: string): () => void {
  ensurePrivateDir(runtimeDir);
  const file = path.join(runtimeDir, "vaultd.lock");
  if (!tryCreate(file) && !(reapStale(file) && tryCreate(file))) {
    throw new DaemonAlreadyRunningError();
  }
  return () => {
    try {
      if (fs.readFileSync(file, "utf8") === String(process.pid)) fs.rmSync(file, { force: true });
    } catch {
      // already gone
    }
  };
}
