import os from "node:os";
import path from "node:path";

export type VaultPaths = {
  dataDir: string;
  runtimeDir: string;
  backupsDir: string;
  dbFile: string;
};

const APP = "agent-vault";

/** Unset, empty, or (per the XDG spec) relative values count as not set. */
function xdg(value: string | undefined): string | undefined {
  return value && path.posix.isAbsolute(value) ? value : undefined;
}

/**
 * Where the vault keeps its files. `env` and `platform` are injectable so tests never read the
 * real environment. `AGENT_VAULT_HOME` moves everything, runtimeDir included: a sandboxed run must
 * not reach `$XDG_RUNTIME_DIR`.
 */
export function getPaths(
  env: NodeJS.ProcessEnv = process.env,
  platform: NodeJS.Platform = process.platform,
): VaultPaths {
  const p = platform === "win32" ? path.win32 : path.posix;
  const override = env.AGENT_VAULT_HOME || undefined;
  const home = () => env.HOME || os.homedir();

  let dataDir: string;
  let runtimeDir: string | undefined;
  if (override) {
    dataDir = override;
  } else if (platform === "darwin") {
    dataDir = p.join(home(), "Library", "Application Support", APP);
  } else if (platform === "win32") {
    const local = env.LOCALAPPDATA || p.join(env.USERPROFILE || os.homedir(), "AppData", "Local");
    dataDir = p.join(local, APP);
  } else {
    dataDir = p.join(xdg(env.XDG_DATA_HOME) ?? p.join(home(), ".local", "share"), APP);
    const run = xdg(env.XDG_RUNTIME_DIR);
    if (run) runtimeDir = p.join(run, APP);
  }

  return {
    dataDir,
    runtimeDir: runtimeDir ?? p.join(dataDir, "run"),
    backupsDir: p.join(dataDir, "backups"),
    dbFile: p.join(dataDir, "vault.db"),
  };
}
