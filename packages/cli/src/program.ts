import { Command } from "commander";
import { auditCommand } from "./commands/audit.js";
import { bundleCommand } from "./commands/bundle.js";
import { daemonCommand } from "./commands/daemon.js";
import { doctorCommand } from "./commands/doctor.js";
import { grabCommand } from "./commands/grab.js";
import { guardCommand } from "./commands/guard.js";
import { helperCommand } from "./commands/helper.js";
import { hookCommand } from "./commands/hook.js";
import { initCommand } from "./commands/init.js";
import { installCommand } from "./commands/install.js";
import { listCommand } from "./commands/list.js";
import { mcpCommand } from "./commands/mcp.js";
import { importCommand, migrateCommand } from "./commands/migrate.js";
import { recoverCommand } from "./commands/recover.js";
import { rmCommand } from "./commands/rm.js";
import { runCommand } from "./commands/run.js";
import { scanCommand } from "./commands/scan.js";
import { setCommand } from "./commands/set.js";
import { statusCommand } from "./commands/status.js";
import { uninstallCommand } from "./commands/uninstall.js";
import { describeError } from "./context.js";
import { CliError, exitWith } from "./errors.js";

/** Run the CLI: parse `argv`, report a failure on stderr, and exit. */
export async function runCli(argv: string[], version: string): Promise<void> {
  const program = new Command()
    .name("agent-vault")
    .description("a local vault so AI agents can use credentials without seeing them")
    .version(version)
    .showHelpAfterError();

  for (const register of [
    initCommand,
    recoverCommand,
    statusCommand,
    setCommand,
    grabCommand,
    listCommand,
    rmCommand,
    runCommand,
    bundleCommand,
    migrateCommand,
    importCommand,
    scanCommand,
    guardCommand,
    auditCommand,
    helperCommand,
    hookCommand,
    installCommand,
    uninstallCommand,
    doctorCommand,
    mcpCommand,
    daemonCommand,
  ]) {
    register(program);
  }

  try {
    await program.parseAsync(argv);
  } catch (err) {
    process.stderr.write(`agent-vault: ${describeError(err)}\n`);
    await exitWith(err instanceof CliError ? err.exitCode : 1);
  }
  // Open handles (a stdin that was read, a socket) must not keep the process alive.
  await exitWith(0);
}
