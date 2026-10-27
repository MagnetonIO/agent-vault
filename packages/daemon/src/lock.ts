import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ensurePrivateDir } from "@agent-vault/platform";
import { DaemonAlreadyRunningError, RecoveryInProgressError } from "./errors.js";

/** An empty or unparseable lock this old is a crashed starter's, not one mid-write. */
const STALE_UNPARSEABLE_MS = 5000;

export const lockPath = (runtimeDir: string): string => path.join(runtimeDir, "vaultd.lock");

/**
 * Identifies this boot of the machine, so a lock left by a pid from before a reboot is not
 * mistaken for a live daemon when the OS hands the pid to something else. "" if unreadable or
 * unavailable (Windows uses uptime instead, see `isStale`), which `sameBoot` treats as "cannot
 * tell", never as "different".
 *   Linux: /proc/sys/kernel/random/boot_id. macOS: kern.bootsessionuuid.
 */
export function readBootId(platform: NodeJS.Platform = process.platform): string {
  try {
    if (platform === "linux") {
      return fs.readFileSync("/proc/sys/kernel/random/boot_id", "utf8").trim();
    }
    if (platform === "darwin") {
      return execFileSync("/usr/sbin/sysctl", ["-n", "kern.bootsessionuuid"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim();
    }
  } catch {
    // fall through
  }
  return "";
}

export function sameBoot(a: string, b: string): boolean {
  return a === "" || b === "" || a === b;
}

const uptimeMs = (): number => os.uptime() * 1000;

/** EPERM means the process exists but belongs to someone else: still alive. */
function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

type LockInfo = { pid: number; bootId: string; uptimeMs?: number; startedAt: string };

function parseLock(text: string): LockInfo | null {
  try {
    const v = JSON.parse(text) as Partial<LockInfo> | null;
    if (
      v &&
      typeof v === "object" &&
      Number.isInteger(v.pid) &&
      (v.pid as number) > 0 &&
      typeof v.bootId === "string"
    ) {
      return v as LockInfo;
    }
  } catch {
    // not JSON
  }
  return null;
}

/** Create the lock file. Returns what it holds, or null if it already exists. */
function tryCreate(file: string, platform: NodeJS.Platform): string | null {
  const text = JSON.stringify({
    pid: process.pid,
    bootId: readBootId(platform),
    uptimeMs: uptimeMs(),
    startedAt: new Date().toISOString(),
  } satisfies LockInfo);
  let fd: number;
  try {
    fd = fs.openSync(file, "wx", 0o600);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") return null;
    throw err;
  }
  try {
    fs.writeSync(fd, text);
  } catch (err) {
    fs.closeSync(fd);
    fs.rmSync(file, { force: true });
    throw err;
  }
  fs.closeSync(fd);
  return text;
}

/** Is the lock's holder gone? A live pid from this boot is never stale, whatever else is true. */
function isStale(text: string, mtimeMs: number, platform: NodeJS.Platform): boolean {
  const info = parseLock(text);
  if (info) {
    if (!isAlive(info.pid)) return true;
    // Windows has no boot id, and its wall clock can step; uptime only ever resets on a reboot.
    if (platform === "win32")
      return typeof info.uptimeMs === "number" && uptimeMs() < info.uptimeMs;
    return !sameBoot(info.bootId, readBootId(platform));
  }
  // Legacy lock (a bare pid) or garbage.
  const trimmed = text.trim();
  if (/^\d+$/.test(trimmed) && Number(trimmed) > 0) return !isAlive(Number(trimmed));
  return Date.now() - mtimeMs > STALE_UNPARSEABLE_MS;
}

/**
 * Remove `file` if its holder is gone. True if the way is clear (removed, or already vanished).
 * The file is renamed aside first, so of several racing reapers only one takes it, and a lock a
 * new holder created in the meantime is put back instead of deleted.
 */
function reapStale(file: string, platform: NodeJS.Platform): boolean {
  let text: string;
  let mtimeMs: number;
  try {
    text = fs.readFileSync(file, "utf8");
    mtimeMs = fs.statSync(file).mtimeMs;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return true;
    throw err;
  }
  if (!isStale(text, mtimeMs, platform)) return false;

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

function acquireAt(
  runtimeDir: string,
  file: string,
  platform: NodeJS.Platform,
  busy: () => Error,
): () => void {
  ensurePrivateDir(runtimeDir);
  const written =
    tryCreate(file, platform) ?? (reapStale(file, platform) ? tryCreate(file, platform) : null);
  if (written === null) throw busy();
  return () => {
    try {
      if (fs.readFileSync(file, "utf8") === written) fs.rmSync(file, { force: true });
    } catch {
      // already gone
    }
  };
}

/**
 * Take the single-instance lock `<runtimeDir>/vaultd.lock`, which holds `{ pid, bootId, uptimeMs, startedAt }`.
 * Synchronous, so concurrent starters (even in one process) are strictly ordered.
 *
 * An existing lock is reaped once, and only if its pid is dead or it was written in an earlier
 * boot (boot id; on Windows, uptime lower than the lock's). A live pid from this boot is never reaped, even if it is not really a daemon (a reused
 * pid): that throws DaemonAlreadyRunningError naming the file so the user can delete it. Returns
 * the release function, which only removes the file while it still holds what we wrote.
 */
export function acquireLock(
  runtimeDir: string,
  platform: NodeJS.Platform = process.platform,
): () => void {
  const file = lockPath(runtimeDir);
  return acquireAt(runtimeDir, file, platform, () => new DaemonAlreadyRunningError(file));
}

export const recoverLockPath = (runtimeDir: string): string =>
  path.join(runtimeDir, "recover.lock");

/**
 * Claim `<runtimeDir>/recover.lock` for `agent-vault recover`, which must own the only daemon while
 * it replaces the root key. Same format and stale rules as vaultd.lock. Throws
 * RecoveryInProgressError while another live recover holds it.
 */
export function acquireRecoverLock(
  runtimeDir: string,
  platform: NodeJS.Platform = process.platform,
): () => void {
  return acquireAt(
    runtimeDir,
    recoverLockPath(runtimeDir),
    platform,
    () => new RecoveryInProgressError(),
  );
}

/** Is a recover running? A lock whose owner is gone is reaped and does not count. */
export function recoveryInProgress(
  runtimeDir: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  return !reapStale(recoverLockPath(runtimeDir), platform);
}
