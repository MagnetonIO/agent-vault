import { checkDiff, installHook, uninstallHook } from "@agent-vault/adapters";
import type { Command } from "commander";
import { CliError, exitWith } from "../errors.js";
import { say, warn } from "../output.js";

export function guardCommand(program: Command): void {
  const guard = program.command("guard").description("stop secrets from being committed to git");

  guard
    .command("check")
    .description("fail if the added lines of a diff hold a secret")
    .option("--staged", "check what is staged (the working-tree diff otherwise)")
    .action(async (opts: { staged?: boolean }) => {
      const hits = await checkDiff({ cwd: process.cwd(), staged: opts.staged === true }).catch(
        (err: Error) => {
          throw new CliError(err.message, 2);
        },
      );
      if (hits.length === 0) return;
      for (const h of hits) say(`${h.file}:${h.line} ${h.fingerprint}`);
      warn(
        `agent-vault: ${hits.length} possible secret(s) in the added lines. Use a vault:// reference, or skip this check once with: git commit --no-verify`,
      );
      await exitWith(1);
    });

  guard
    .command("install")
    .description("add a git pre-commit hook that runs `guard check --staged`")
    .action(async () => {
      const { hook, chained } = await installHook({ cwd: process.cwd() }).catch((err: Error) => {
        throw new CliError(err.message, 2);
      });
      say(`installed ${hook}`);
      if (chained) say(`your existing hook still runs after it: ${chained}`);
    });

  guard
    .command("uninstall")
    .description("remove the pre-commit hook and restore the one it replaced")
    .action(async () => {
      const removed = await uninstallHook({ cwd: process.cwd() }).catch((err: Error) => {
        throw new CliError(err.message, 2);
      });
      say(removed ? "removed the agent-vault pre-commit hook" : "no agent-vault hook is installed");
    });
}
