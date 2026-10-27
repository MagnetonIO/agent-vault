import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ensurePrivateDir, getPaths, PASSPHRASE_ENV, type VaultPaths } from "@agent-vault/platform";
import { daemonRunArgv } from "../autostart.js";
import { ServiceError } from "./errors.js";
import * as launchd from "./launchd.js";
import * as schtasks from "./schtasks.js";
import * as systemd from "./systemd.js";

export { ServiceError } from "./errors.js";

/** The headless unlock for the keyfile store. Read only to see whether it is set; never written. */

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
  /** Who the Windows logon task runs for, as `DOMAIN\user`. Default: the current user. */
  user?: string;
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
  /** Things to tell the user after a success. */
  notes: string[];
  /** Uninstall only: false when there was nothing to remove. */
  installed: boolean;
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

const taskUser = (o: ServiceOptions, env: NodeJS.ProcessEnv): string => {
  if (o.user) return o.user;
  const name = os.userInfo().username;
  return env.USERDOMAIN ? `${env.USERDOMAIN}\\${name}` : name;
};

async function installTask(o: ServiceOptions, r: Resolved, argv: readonly string[]) {
  const exe = schtasks.schtasksExe(r.env);
  // schtasks reads the definition from a file; keep it in the private data dir, and only briefly.
  ensurePrivateDir(r.paths.dataDir);
  const xmlFile = path.join(r.paths.dataDir, `task-${process.pid}.xml`);
  fs.writeFileSync(
    xmlFile,
    schtasks.encodeTaskXml(schtasks.renderTaskXml({ argv, user: taskUser(o, r.env) })),
    { mode: 0o600 },
  );
  try {
    await mustRun(r.run, schtasks.createArgv(exe, xmlFile));
  } finally {
    fs.rmSync(xmlFile, { force: true });
  }
}

export async function installService(o: InstallOptions): Promise<ServiceResult> {
  const r = resolve(o);
  const passphraseSet = Boolean(r.env[PASSPHRASE_ENV]);
  if (o.keystore === "keyfile" && !passphraseSet) {
    throw new ServiceError(
      `the keyfile store needs a passphrase at daemon start; use --keystore os or set ${PASSPHRASE_ENV} in the service environment yourself`,
    );
  }
  const argv = o.argv ?? daemonRunArgv();
  // The service gets AGENT_VAULT_HOME and nothing else, so it finds the same vault.
  const vaultHome = r.env.AGENT_VAULT_HOME ? r.paths.dataDir : undefined;
  const warnings: string[] = [];
  const notes = [`The service pins ${argv[0]}; reinstall after upgrading Node.`];
  if (o.keystore === "keyfile") {
    warnings.push(
      `WARNING: the passphrase is not written to the service. Unless ${PASSPHRASE_ENV} is in the service's own environment, the daemon cannot unlock the keyfile store and will exit at start.`,
    );
  }

  if (r.platform === "win32") {
    if (vaultHome) {
      throw new ServiceError(
        "a Task Scheduler task cannot carry AGENT_VAULT_HOME; unset it to install the default vault's service",
      );
    }
    await installTask(o, r, argv);
    return { unitFile: undefined, warnings, notes, installed: true };
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
      await r.run(launchd.deactivateArgv(uid));
      await mustRun(r.run, launchd.activateArgv(uid, unitFile));
    } else {
      for (const cmd of systemd.activateArgvs()) await mustRun(r.run, cmd);
    }
  } catch (err) {
    if (r.platform === "linux") {
      // `enable` may have linked the unit before `--now` failed: undo it before the unit goes.
      await r.run(systemd.deactivateArgv());
      fs.rmSync(unitFile, { force: true });
      await r.run(systemd.reloadArgv());
    } else {
      fs.rmSync(unitFile, { force: true });
    }
    throw err;
  }
  return { unitFile, warnings, notes, installed: true };
}

export async function uninstallService(o: ServiceOptions): Promise<ServiceResult> {
  const r = resolve(o);
  const warnings: string[] = [];
  const notes: string[] = [];
  const failed = (argv: readonly string[], code: number, stderr: string) =>
    `${show(argv)} failed (exit ${code}): ${stderr.trim()}`;

  if (r.platform === "win32") {
    const exe = schtasks.schtasksExe(r.env);
    // Its exit code tells "no such task" from a failed delete without reading localized text.
    if ((await r.run(schtasks.queryArgv(exe))).code !== 0) {
      return { unitFile: undefined, warnings, notes, installed: false };
    }
    const del = schtasks.deleteArgv(exe);
    const { code, stderr } = await r.run(del);
    if (code !== 0) warnings.push(failed(del, code, stderr));
    return { unitFile: undefined, warnings, notes, installed: true };
  }

  const unitFile = r.platform === "darwin" ? launchd.plistPath(r.home) : systemd.unitPath(r.home);
  const existed = fs.existsSync(unitFile);
  // Stop and unload first. A failure with a unit file present is worth a warning; without one it
  // only means nothing was loaded.
  const stop =
    r.platform === "darwin" ? launchd.deactivateArgv(uidOf(o)) : systemd.deactivateArgv();
  const res = await r.run(stop);
  const installed = existed || res.code === 0;
  if (!installed) return { unitFile, warnings, notes, installed };
  if (res.code !== 0) warnings.push(failed(stop, res.code, res.stderr));

  fs.rmSync(unitFile, { force: true });
  if (r.platform === "linux") {
    // Reload only after the file is gone, or systemd keeps the unit in memory.
    const reload = systemd.reloadArgv();
    const again = await r.run(reload);
    if (again.code !== 0) warnings.push(failed(reload, again.code, again.stderr));
  }
  return { unitFile, warnings, notes, installed };
}
