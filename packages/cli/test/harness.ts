import { type ChildProcess, spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { connect } from "@agent-vault/daemon";
import { getPaths, ipcEndpoint } from "@agent-vault/platform";

const here = path.dirname(fileURLToPath(import.meta.url));

/** The BUILT CLI: `pnpm build` comes before `pnpm test`. */
export const CLI = path.resolve(here, "../dist/main.js");

export const PASSPHRASE = "e2e passphrase 7731";

export type Result = { code: number | null; stdout: string; stderr: string };

export type Sandbox = {
  dir: string;
  home: string;
  /** The test clipboard (a file); see AGENT_VAULT_TEST_CLIPBOARD_FILE. */
  clipboard: string;
  env: NodeJS.ProcessEnv;
  /** Run the CLI. `stdin` is written and closed; omitted, stdin is closed at once. */
  cli(
    args: string[],
    opts?: { stdin?: string; env?: NodeJS.ProcessEnv; cwd?: string },
  ): Promise<Result>;
  /** The pid of the sandbox's daemon, or null if none answers. Never starts one. */
  daemonPid(): Promise<number | null>;
  /** `daemon stop`, then wait for the process to be gone. Throws if it is not. */
  stopDaemon(): Promise<void>;
  remove(): void;
};

/** A sandbox that never reaches the real keychain, clipboard or home (AGENTS.md). */
export function makeSandbox(keystore: "keyfile" | "os" = "keyfile"): Sandbox {
  if (!fs.existsSync(CLI)) throw new Error(`${CLI} is missing: run pnpm build first`);
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "avc-")));
  const home = path.join(dir, "vault");
  fs.mkdirSync(home, { recursive: true });
  fs.writeFileSync(path.join(home, "config.json"), JSON.stringify({ keystore }));
  const clipboard = path.join(dir, "clipboard.txt");
  fs.writeFileSync(clipboard, "");
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: dir,
    USERPROFILE: dir,
    CODEX_HOME: dir,
    AGENT_VAULT_HOME: home,
    XDG_DATA_HOME: path.join(dir, "xdg-data"),
    XDG_RUNTIME_DIR: path.join(dir, "xdg-run"),
    AGENT_VAULT_KEYFILE_PASSPHRASE: PASSPHRASE,
    AGENT_VAULT_TEST_CLIPBOARD_FILE: clipboard,
  };

  const cli: Sandbox["cli"] = (args, opts = {}) =>
    new Promise((resolve, reject) => {
      const child: ChildProcess = spawn(process.execPath, [CLI, ...args], {
        env: { ...env, ...opts.env },
        ...(opts.cwd !== undefined && { cwd: opts.cwd }),
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
      });
      let stdout = "";
      let stderr = "";
      child.stdout?.setEncoding("utf8").on("data", (c: string) => (stdout += c));
      child.stderr?.setEncoding("utf8").on("data", (c: string) => (stderr += c));
      child.once("error", reject);
      child.once("close", (code) => resolve({ code, stdout, stderr }));
      child.stdin?.on("error", () => {});
      child.stdin?.end(opts.stdin ?? "");
    });

  const sandbox: Sandbox = {
    dir,
    home,
    clipboard,
    env,
    cli,
    async daemonPid() {
      const client = await connect(ipcEndpoint(getPaths({ AGENT_VAULT_HOME: home }))).catch(
        () => null,
      );
      if (!client) return null;
      try {
        return (await client.call<{ pid: number }>("status")).pid;
      } catch {
        return null;
      } finally {
        client.close();
      }
    },
    async stopDaemon() {
      const pid = await sandbox.daemonPid();
      await cli(["daemon", "stop"]);
      if (pid === null) return;
      for (let i = 0; i < 100 && alive(pid); i++) await new Promise((r) => setTimeout(r, 50));
      if (alive(pid)) {
        process.kill(pid, "SIGKILL");
        throw new Error(`vaultd ${pid} was still running after daemon stop`);
      }
    },
    remove() {
      fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    },
  };
  return sandbox;
}

export function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}
