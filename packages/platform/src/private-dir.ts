import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const SID_SYSTEM = "*S-1-5-18";
const SID_ADMINISTRATORS = "*S-1-5-32-544";

/**
 * The `icacls` argument lists that lock a Windows dir to one user, in the order Spike S2 verified.
 * `(OI)(CI)` lets files created inside inherit the grant. SYSTEM and Administrators are explicit
 * ACEs on a new dir, so `/inheritance:r` alone leaves them; they are removed by SID because the
 * names are localized.
 */
export function icaclsCommands(dir: string, username: string): string[][] {
  return [
    [dir, "/inheritance:r", "/grant:r", `${username}:(OI)(CI)F`],
    [dir, "/remove", SID_SYSTEM, "/remove", SID_ADMINISTRATORS],
  ];
}

/** Absolute path of icacls, so a hostile PATH entry cannot stand in for it. */
export function icaclsExe(env: NodeJS.ProcessEnv = process.env): string {
  return path.win32.join(env.SystemRoot ?? "C:\\Windows", "System32", "icacls.exe");
}

/** True when `dir` is a symlink, a junction, or any other reparse point readlink can resolve. */
function isLink(dir: string, st: fs.Stats): boolean {
  if (st.isSymbolicLink()) return true;
  try {
    fs.readlinkSync(dir);
    return true;
  } catch {
    return false;
  }
}

/**
 * Create `dir` (and parents) readable by this user only.
 *
 * Either way the final component must be a real directory: a symlink, junction or file is
 * refused before anything is changed through it.
 * POSIX: mode 0700. An existing dir must be owned by this uid, else this throws; a looser mode is
 * tightened to 0700.
 * Windows: fs modes do not set ACLs, so `icacls` is run on the dir.
 */
export function ensurePrivateDir(dir: string, platform: NodeJS.Platform = process.platform): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  const st = fs.lstatSync(dir); // lstat: a symlink is not a directory here
  if (isLink(dir, st)) throw new Error(`${dir} is a symlink or junction, refusing to use it`);
  if (!st.isDirectory()) throw new Error(`${dir} is not a directory`);

  if (platform === "win32") {
    for (const args of icaclsCommands(dir, os.userInfo().username)) {
      execFileSync(icaclsExe(), args, { stdio: "pipe" });
    }
    return;
  }

  const uid = process.getuid?.();
  if (uid !== undefined && st.uid !== uid) {
    throw new Error(`${dir} is owned by uid ${st.uid}, not by this user (uid ${uid})`);
  }
  if ((st.mode & 0o077) !== 0) fs.chmodSync(dir, 0o700);
}
