import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import type { VaultPaths } from "./paths.js";

export type IpcEndpoint =
  | { kind: "unix"; path: string }
  | { kind: "tcp"; endpointFile: string; tokenFile: string };

/** sizeof(sun_path) minus the NUL, in UTF-8 bytes (Spike S2: the measured hard limits are 1 more). */
const SOCKET_MAX_BYTES = { darwin: 103, other: 107 } as const;

/**
 * Where the daemon listens and the CLI connects, per Spike S2.
 *
 * POSIX: a unix socket in runtimeDir. If that path exceeds the byte limit, a hashed path in a
 * per-uid dir under the temp dir instead; callers run `ensurePrivateDir(path.dirname(path))` first,
 * which fails closed if another user pre-created the (predictable) fallback dir.
 * Windows: loopback TCP. Only the file locations are decided here; the mutual handshake is the
 * daemon's. There is deliberately no named-pipe kind.
 */
export function ipcEndpoint(
  paths: VaultPaths,
  platform: NodeJS.Platform = process.platform,
  env: NodeJS.ProcessEnv = process.env,
): IpcEndpoint {
  if (platform === "win32") {
    return {
      kind: "tcp",
      endpointFile: path.win32.join(paths.runtimeDir, "endpoint.json"),
      tokenFile: path.win32.join(paths.runtimeDir, "token"),
    };
  }

  const max = platform === "darwin" ? SOCKET_MAX_BYTES.darwin : SOCKET_MAX_BYTES.other;
  const normal = path.posix.join(paths.runtimeDir, "vaultd.sock");
  if (Buffer.byteLength(normal) <= max) return { kind: "unix", path: normal };

  const digest = createHash("sha256").update(normal).digest("hex").slice(0, 16);
  const tmp = env.TMPDIR || os.tmpdir();
  const short = path.posix.join(tmp, `av-${process.getuid?.() ?? 0}`, `${digest}.sock`);
  if (Buffer.byteLength(short) > max) {
    throw new Error(
      `socket path too long even for the fallback (${Buffer.byteLength(short)} > ${max} bytes): ${short}`,
    );
  }
  return { kind: "unix", path: short };
}
