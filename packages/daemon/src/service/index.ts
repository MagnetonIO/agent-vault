import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ensurePrivateDir, getPaths, type VaultPaths } from "@agent-vault/platform";
import { daemonRunArgv } from "../autostart.js";
import { ServiceError } from "./errors.js";
import * as launchd from "./launchd.js";
import * as schtasks from "./schtasks.js";
import * as systemd from "./systemd.js";

export { ServiceError } from "./errors.js";

/** The headless unlock for the keyfile store. Read only to see whether it is set; never written. */
const KEYFILE_PASSPHRASE_ENV = "AGENT_VAULT_KEYFILE_PASSPHRASE";

export type CommandRunner = (argv: readonly string[]) => Promise<{ code: number; stderr: string }>;

/** Runs `argv[0]` directly (no shell). A command that cannot be started is reported as code -1. */
export const runCommand: CommandRunner = (argv) =>
  new Promise((resolve) => {
    const [file, ...args] = argv;
    if (!file) return resolve({ code: -1, stderr: "empty command" });
    execFile(file, args, { windowsHide: true }, (err, _stdout, stderr) => {
      if (!err) return resolve({ code: 0, stderr });
      const code = typeof err.code === "number" ? err.code : -1;
      resolve({ code, stderr: stderr || err.message });
    });
  });

/** Every field is injectable so tests never touch the real home, launchctl, systemctl or schtasks. */
export type ServiceOptions = {
  platform?: NodeJS.Platform;
  home?: string;
  /** The user id for `launchctl gui/<uid>`. Default: the current user. */
  uid?: number;
  env?: NodeJS.ProcessEnv;
  paths?: VaultPaths;
  /** The command the service runs. Default: this CLI's `daemon run`, resolved now. */
  argv?: readonly string[];
  run?: CommandRunner;
};

export type InstallOptions = ServiceOptions & { keystore: "os" | "keyfile" };

export type ServiceResult = {
  /** The unit file written or removed; none on Windows, where the task lives in Task Scheduler. */
  unitFile: string | undefined;
  /** Things that went wrong but did not stop the command. */
  warnings: string[];
};

type Resolved = {
  platform: "darwin" | "linux" | "win32";
  home: string;
  env: NodeJS.ProcessEnv;
  paths: VaultPaths;
  p: typeof path.posix;
  run: CommandRunner;
};

function resolve(o: ServiceOptions): Resolved {
  const platform = o.platform ?? process.platform;
  if (platform !== "darwin" && platform !== "linux" && platform !== "win32") {
    throw new ServiceError(`no service manager support for ${platform}`);
  }
  const env = o.env ?? process.env;
  return {
    platform,
    home: o.home ?? os.homedir(),
    env,
    paths: o.paths ?? getPaths(env, platform),
    p: platform === "win32" ? path.win32 : path.posix,
    run: o.run ?? runCommand,
  };
}

const uidOf = (o: ServiceOptions): number => {
  const uid = o.uid ?? process.getuid?.();
  if (uid === undefined) throw new ServiceError("cannot tell the user id for launchctl");
  return uid;
};

const show = (argv: readonly string[]): string => argv.join(" ");

async function mustRun(run: CommandRunner, argv: readonly string[]): Promise<void> {
  const { code, stderr } = await run(argv);
  if (code !== 0) throw new ServiceError(`${show(argv)} failed (exit ${code}): ${stderr.trim()}`);
}

export async function installService(o: InstallOptions): Promise<ServiceResult> {
  const r = resolve(o);
  if (o.keystore === "keyfile" && !r.env[KEYFILE_PASSPHRASE_ENV]) {
    throw new ServiceError(
      `the keyfile store needs a passphrase at daemon start; use --keystore os or set ${KEYFILE_PASSPHRASE_ENV} in the service environment yourself`,
    );
  }
  const argv = o.argv ?? daemonRunArgv();
  // The service gets AGENT_VAULT_HOME and nothing else, so it finds the same vault.
  const vaultHome = r.env.AGENT_VAULT_HOME ? r.paths.dataDir : undefined;

  if (r.platform === "win32") {
    if (vaultHome) {
      throw new ServiceError(
        "a Task Scheduler task cannot carry AGENT_VAULT_HOME; unset it to install the default vault's service",
      );
    }
    await mustRun(r.run, schtasks.createArgv(schtasks.schtasksExe(r.env), argv));
    return { unitFile: undefined, warnings: [] };
  }

  const unitFile = r.platform === "darwin" ? launchd.plistPath(r.home) : systemd.unitPath(r.home);
  const logFile = r.p.join(r.paths.dataDir, "logs", "vaultd.log");
  const text =
    r.platform === "darwin"
      ? launchd.renderPlist({ argv, logFile, vaultHome })
      : systemd.renderUnit({ argv, vaultHome });

  // launchd opens the log before it starts the daemon, so its directory must exist.
  if (r.platform === "darwin") ensurePrivateDir(r.p.dirname(logFile));
  fs.mkdirSync(path.dirname(unitFile), { recursive: true });
  fs.writeFileSync(unitFile, text, { mode: 0o644 });
  try {
    if (r.platform === "darwin") {
      const uid = uidOf(o);
      // Bootstrapping a loaded service fails; reinstalling must work, so unload first.
      await r.run(launchd.deactivateArgv(uid, unitFile));
      await mustRun(r.run, launchd.activateArgv(uid, unitFile));
    } else {
      for (const cmd of systemd.activateArgvs()) await mustRun(r.run, cmd);
    }
  } catch (err) {
    fs.rmSync(unitFile, { force: true });
    throw err;
  }
  return { unitFile, warnings: [] };
}

export async function uninstallService(o: ServiceOptions): Promise<ServiceResult> {
  const r = resolve(o);
  const warnings: string[] = [];
  // A service that was never loaded is not an error here: keep going and delete what is left.
  const tryRun = async (argv: readonly string[]) => {
    const { code, stderr } = await r.run(argv);
    if (code !== 0) warnings.push(`${show(argv)} failed (exit ${code}): ${stderr.trim()}`);
  };

  if (r.platform === "win32") {
    await tryRun(schtasks.deleteArgv(schtasks.schtasksExe(r.env)));
    return { unitFile: undefined, warnings };
  }

  const unitFile = r.platform === "darwin" ? launchd.plistPath(r.home) : systemd.unitPath(r.home);
  if (r.platform === "darwin") {
    await tryRun(launchd.deactivateArgv(uidOf(o), unitFile));
  } else {
    for (const cmd of systemd.deactivateArgvs()) await tryRun(cmd);
  }
  fs.rmSync(unitFile, { force: true });
  return { unitFile, warnings };
}
