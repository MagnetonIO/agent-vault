import fs from "node:fs";
import {
  DaemonAlreadyRunningError,
  installService,
  recoveryInProgress,
  ServiceError,
  startDaemon,
  uninstallService,
} from "@agent-vault/daemon";
import {
  getPaths,
  openKeyfileStore,
  openOsKeyring,
  type RootKeyStore,
  type VaultPaths,
  WrongPassphraseError,
} from "@agent-vault/platform";
import { type Command, Option } from "commander";
import {
  EXIT_WRONG_PASSPHRASE,
  keyfilePath,
  PASSPHRASE_ENV,
  readConfig,
  WRONG_PASSPHRASE_MESSAGE,
} from "../config.js";
import { LOCKED_MESSAGE, RECOVERY_IN_PROGRESS } from "../context.js";
import { stopDaemon } from "../daemon-control.js";
import { CliError, exitWith } from "../errors.js";
import { say, warn } from "../output.js";
import { isTty, promptPassphrase } from "../tty.js";

const STDIN_PASSPHRASE_TIMEOUT_MS = 5000;

/** Exactly one line from stdin, then stdin is closed. Gives up after `timeoutMs`. */
export function readPassphraseLine(
  input: NodeJS.ReadableStream & { destroy?: () => unknown } = process.stdin,
  timeoutMs = STDIN_PASSPHRASE_TIMEOUT_MS,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    let text = "";
    const finish = (err: CliError | null, line = "") => {
      clearTimeout(timer);
      input.removeListener("data", onData);
      input.removeListener("end", onEnd);
      input.destroy?.();
      if (err) reject(err);
      else resolve(line);
    };
    const onData = (chunk: Buffer | string) => {
      text += chunk.toString();
      const nl = text.indexOf("\n");
      if (nl !== -1) finish(null, text.slice(0, nl).replace(/\r$/, ""));
    };
    const onEnd = () => {
      if (text === "") finish(new CliError("no passphrase arrived on stdin"));
      else finish(null, text.replace(/\r$/, ""));
    };
    const timer = setTimeout(
      () => finish(new CliError("timed out waiting for the passphrase on stdin")),
      timeoutMs,
    );
    input.on("data", onData);
    input.on("end", onEnd);
  });
}

/**
 * The key store the config names. A keyfile needs its passphrase: from stdin when a CLI spawned
 * this daemon (`--passphrase-stdin`), else from the environment, else the terminal.
 */
async function openConfiguredStore(paths: VaultPaths, fromStdin: boolean): Promise<RootKeyStore> {
  if (readConfig(paths) === "os") return openOsKeyring();
  let passphrase: string | undefined;
  if (fromStdin) {
    passphrase = await readPassphraseLine();
  } else {
    passphrase = process.env[PASSPHRASE_ENV];
    // Unsets it for this process and what it starts. It cannot clear the block the OS keeps from
    // exec time, which is why a CLI that autostarts a daemon uses --passphrase-stdin instead.
    delete process.env[PASSPHRASE_ENV];
    if (!passphrase) {
      if (!isTty()) throw new CliError(LOCKED_MESSAGE);
      passphrase = await promptPassphrase(!fs.existsSync(keyfilePath(paths)));
    }
  }
  if (!passphrase) throw new CliError(LOCKED_MESSAGE);
  return openKeyfileStore(keyfilePath(paths), passphrase);
}

async function runDaemon(opts: { passphraseStdin?: boolean; recovering?: boolean }): Promise<void> {
  const paths = getPaths();
  // `recover` owns the only daemon while it replaces the root key; it starts its own with
  // --recovering.
  if (!opts.recovering && recoveryInProgress(paths.runtimeDir)) {
    throw new CliError(RECOVERY_IN_PROGRESS);
  }
  const store = await openConfiguredStore(paths, opts.passphraseStdin === true);
  let handle: Awaited<ReturnType<typeof startDaemon>>;
  try {
    handle = await startDaemon({ paths, store });
  } catch (err) {
    // Losing the race to another daemon is how a second start ends.
    if (err instanceof DaemonAlreadyRunningError) await exitWith(0);
    if (err instanceof WrongPassphraseError) {
      throw new CliError(WRONG_PASSPHRASE_MESSAGE, EXIT_WRONG_PASSPHRASE);
    }
    throw err;
  }
  const shutdown = () => void handle.close();
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
  await handle.closed;
  await exitWith(0);
}

/** Service-manager failures are the user's to fix: print the message, not a stack. */
async function viaService<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof ServiceError) throw new CliError(err.message);
    throw err;
  }
}

async function installDaemon(): Promise<void> {
  const keystore = readConfig(getPaths());
  const { unitFile, warnings, notes } = await viaService(() => installService({ keystore }));
  say(unitFile ? `installed ${unitFile}` : "registered the logon task agent-vault-daemon");
  for (const note of notes) say(note);
  for (const w of warnings) warn(w);
}

async function uninstallDaemon(): Promise<void> {
  const { unitFile, warnings, installed } = await viaService(() => uninstallService({}));
  for (const w of warnings) warn(`warning: ${w}`);
  if (!installed) say("not installed");
  else say(unitFile ? `removed ${unitFile}` : "removed the logon task agent-vault-daemon");
}

export function daemonCommand(program: Command): void {
  const daemon = program
    .command("daemon")
    .description("the background process that holds the vault");
  daemon
    .command("run")
    .description(
      `run vaultd in the foreground. A keyfile passphrase is read from ${PASSPHRASE_ENV} or the terminal; a daemon started with it in its own environment keeps it there for its whole life, so prefer the terminal prompt`,
    )
    .addOption(
      new Option(
        "--passphrase-stdin",
        "read the keyfile passphrase as one line on stdin",
      ).hideHelp(),
    )
    .addOption(new Option("--recovering", "started by `agent-vault recover`").hideHelp())
    .action(runDaemon);
  daemon
    .command("stop")
    .description("stop vaultd")
    .action(async () => stopDaemon(getPaths()));
  daemon
    .command("install")
    .description("start vaultd at login (launchd, systemd --user, or Task Scheduler)")
    .action(installDaemon);
  daemon.command("uninstall").description("remove the login service").action(uninstallDaemon);
}
