import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { getPaths, MemoryKeyStore, type VaultPaths } from "@agent-vault/platform";
import { afterEach, beforeEach } from "vitest";
import { initVault, openDb, type Vault } from "../src/index.js";

export const enc = new TextEncoder();

export type Env = {
  paths: VaultPaths;
  store: MemoryKeyStore;
  /** A fresh vault in the temp dir; closed automatically after the test. */
  newVault(): Promise<Vault>;
  /** Run raw SQL against the vault file, as an attacker with disk access would. */
  withRawDb<T>(fn: (db: ReturnType<typeof openDb>) => T): T;
};

/** Sandboxed vault location (temp dir, MemoryKeyStore). Call once per describe block. */
export function useVaultEnv(): Env {
  let tmp: string;
  const opened: Vault[] = [];
  const env = {} as Env;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), "av-core-"));
    env.paths = getPaths({ AGENT_VAULT_HOME: path.join(tmp, "vault") }, process.platform);
    env.store = new MemoryKeyStore();
    env.newVault = async () => {
      const { vault } = await initVault({ paths: env.paths, store: env.store });
      opened.push(vault);
      return vault;
    };
    env.withRawDb = (fn) => {
      const db = openDb(env.paths.dbFile);
      try {
        return fn(db);
      } finally {
        db.close();
      }
    };
  });

  afterEach(() => {
    for (const v of opened.splice(0)) v.close();
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  return env;
}
