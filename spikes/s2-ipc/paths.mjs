// Prototype of the POSIX socket location rules for packages/platform (getPaths().runtimeDir).
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/** UTF-8 byte length limit of the socket path: sizeof(sun_path) minus 1 byte for the NUL. */
export const SOCKET_MAX_BYTES = { darwin: 103, linux: 107 };

export function dirsFor({ env, platform, home }) {
  if (platform === "darwin") {
    const dataDir =
      env.AGENT_VAULT_HOME ?? path.join(home, "Library", "Application Support", "agent-vault");
    return { dataDir, runtimeDir: path.join(dataDir, "run") };
  }
  const dataDir =
    env.AGENT_VAULT_HOME ??
    path.join(env.XDG_DATA_HOME || path.join(home, ".local", "share"), "agent-vault");
  const runtimeDir = env.XDG_RUNTIME_DIR
    ? path.join(env.XDG_RUNTIME_DIR, "agent-vault")
    : path.join(dataDir, "run");
  return { dataDir, runtimeDir };
}

/** Create `dir` as 0700 and refuse anything that is not a real directory we own, closed to others. */
export function ensurePrivateDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = fs.lstatSync(dir); // lstat: a symlink is not a directory here
  if (!st.isDirectory() || st.uid !== process.getuid() || (st.mode & 0o077) !== 0) {
    throw new Error(
      `unsafe ipc dir ${dir} (uid=${st.uid}, mode=${(st.mode & 0o7777).toString(8)})`,
    );
  }
}

/**
 * `{ path, dir, fallback }`. Normal: `<runtimeDir>/<name>`. When that path is longer than the
 * limit in UTF-8 bytes: `<tmpdir>/av-<uid>/<sha256(runtimeDir)[0:16]>.sock`. The fallback dir name
 * is predictable, so ensurePrivateDir() must refuse one that someone else pre-created (fail closed).
 */
export function resolveSocket({
  env = process.env,
  platform = process.platform,
  home = os.homedir(),
  tmpdir = os.tmpdir(),
  name = "vaultd.sock",
} = {}) {
  const max = SOCKET_MAX_BYTES[platform];
  const { runtimeDir } = dirsFor({ env, platform, home });
  const normal = path.join(runtimeDir, name);
  if (Buffer.byteLength(normal) <= max) return { path: normal, dir: runtimeDir, fallback: false };
  const digest = createHash("sha256").update(runtimeDir).digest("hex").slice(0, 16);
  const dir = path.join(tmpdir, `av-${process.getuid()}`);
  const short = path.join(dir, `${digest}.sock`);
  if (Buffer.byteLength(short) > max) {
    throw new Error(
      `socket path too long even for fallback (${Buffer.byteLength(short)} > ${max} bytes): ${short}`,
    );
  }
  return { path: short, dir, fallback: true };
}
