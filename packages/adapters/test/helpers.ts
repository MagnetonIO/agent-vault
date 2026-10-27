import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { connect, type IpcClient, startDaemon } from "@agent-vault/daemon";
import { getPaths, ipcEndpoint, MemoryKeyStore, type VaultPaths } from "@agent-vault/platform";
import { afterEach, beforeEach } from "vitest";

export type Box = {
  dir: string;
  /** Stands in for the user's home. */
  home: string;
  codexHome: string;
  /** The project directory; its name is `proj`. */
  cwd: string;
  paths: VaultPaths;
  client: IpcClient;
};

/** Temp home, CODEX_HOME and project, plus an in-process daemon on a MemoryKeyStore. */
export function useBox(): Box {
  const box = {} as Box;
  let close: (() => Promise<void>) | undefined;
  beforeEach(async () => {
    box.dir = fs.mkdtempSync(path.join(os.tmpdir(), "avm-"));
    box.home = path.join(box.dir, "home");
    box.codexHome = path.join(box.dir, "codex");
    box.cwd = path.join(box.dir, "proj");
    for (const d of [box.home, box.codexHome, box.cwd]) fs.mkdirSync(d, { recursive: true });
    box.paths = getPaths({ AGENT_VAULT_HOME: path.join(box.dir, "v") }, process.platform);
    const daemon = await startDaemon({ paths: box.paths, store: new MemoryKeyStore() });
    box.client = await connect(ipcEndpoint(box.paths));
    close = async () => {
      box.client.close();
      await daemon.close();
    };
    await box.client.call("vault.init", { keystore: "memory" });
  });
  afterEach(async () => {
    await close?.();
    fs.rmSync(box.dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });
  return box;
}

/** The date stamp detection puts in suggested names (UTC). */
export const stamp = (): string => new Date().toISOString().slice(0, 10).replaceAll("-", "");
