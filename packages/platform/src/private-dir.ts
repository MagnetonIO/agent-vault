import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";

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

/**
 * Create `dir` (and parents) readable by this user only.
 *
 * POSIX: mode 0700. An existing dir must be a real directory (not a symlink) owned by this uid,
 * else this throws; a looser mode is tightened to 0700.
 * Windows: fs modes do not set ACLs, so `icacls` is run on the dir.
 */
export function ensurePrivateDir(dir: string, platform: NodeJS.Platform = process.platform): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });

  if (platform === "win32") {
    for (const args of icaclsCommands(dir, os.userInfo().username)) {
      execFileSync("icacls", args, { stdio: "pipe" });
    }
    return;
  }

  const st = fs.lstatSync(dir); // lstat: a symlink is not a directory here
  if (!st.isDirectory()) throw new Error(`${dir} is not a directory`);
  const uid = process.getuid?.();
  if (uid !== undefined && st.uid !== uid) {
    throw new Error(`${dir} is owned by uid ${st.uid}, not by this user (uid ${uid})`);
  }
  if ((st.mode & 0o077) !== 0) fs.chmodSync(dir, 0o700);
}
