import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ensurePrivateDir, type VaultPaths } from "@agent-vault/platform";
import { CliError } from "./errors.js";

export type KeystoreChoice = "os" | "keyfile";

export const KEYSTORE_CHOICES: readonly KeystoreChoice[] = ["os", "keyfile"];

/** What `status` reports as the daemon's key store for each choice. */
export const STORE_KIND: Record<KeystoreChoice, string> = { os: "os-keyring", keyfile: "keyfile" };

/** The headless unlock for the keyfile store (AGENTS.md). Never used for a secret. */
export const PASSPHRASE_ENV = "AGENT_VAULT_KEYFILE_PASSPHRASE";

export const configPath = (paths: VaultPaths): string => path.join(paths.dataDir, "config.json");

/** The keyfile always lives here, whatever else moves. */
export const keyfilePath = (paths: VaultPaths): string => path.join(paths.dataDir, "keyfile");

/** The configured key store; `os` when there is no config yet. */
export function readConfig(paths: VaultPaths): KeystoreChoice {
  let text: string;
  try {
    text = fs.readFileSync(configPath(paths), "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return "os";
    throw new CliError(`could not read ${configPath(paths)}`);
  }
  let keystore: unknown;
  try {
    keystore = (JSON.parse(text) as { keystore?: unknown } | null)?.keystore;
  } catch {
    // reported below
  }
  if (keystore !== "os" && keystore !== "keyfile") {
    throw new CliError(`${configPath(paths)} must be {"keystore": "os" | "keyfile"}`);
  }
  return keystore;
}

/** The raw config file, or null if there is none. For putting it back after a failed `init`. */
export function snapshotConfig(paths: VaultPaths): string | null {
  try {
    return fs.readFileSync(configPath(paths), "utf8");
  } catch {
    return null;
  }
}

/** temp file (0600) + rename, so a reader never sees half a config. */
function writeAtomic(file: string, data: string): void {
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  try {
    fs.writeFileSync(tmp, data, { mode: 0o600, flag: "wx" });
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}

export function writeConfig(paths: VaultPaths, keystore: KeystoreChoice): void {
  ensurePrivateDir(paths.dataDir);
  writeAtomic(configPath(paths), `${JSON.stringify({ keystore })}\n`);
}

export function restoreConfig(paths: VaultPaths, snapshot: string | null): void {
  if (snapshot === null) fs.rmSync(configPath(paths), { force: true });
  else {
    ensurePrivateDir(paths.dataDir);
    writeAtomic(configPath(paths), snapshot);
  }
}
