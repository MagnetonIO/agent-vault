import { statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  applyMigration,
  type Finding,
  type FindingKind,
  findInDotenv,
  findPlaintextSecrets,
  isRemoteHeader,
  type MigrationResult,
} from "@agent-vault/adapters";
import { fingerprint } from "@agent-vault/detect";
import type { Command } from "commander";
import { withDaemon } from "../context.js";
import { CliError } from "../errors.js";
import { say, table } from "../output.js";

const KINDS: FindingKind[] = [
  "dotenv",
  "claude-mcp",
  "codex-mcp",
  "opencode-mcp",
  "opencode-remote-header",
  "claude-remote-header",
];

type Options = { apply?: boolean; json?: boolean };

/** What may be printed about a finding: where it is and a fingerprint, never the value. */
const describe = (f: Finding) => ({
  file: f.file,
  kind: f.kind,
  locator: f.locator,
  envName: f.envName,
  fingerprint: fingerprint(f.detection),
});

function countsByKind(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const kind of KINDS) {
    const n = findings.filter((f) => f.kind === kind).length;
    if (n > 0) counts[kind] = n;
  }
  return counts;
}

async function report(findings: Finding[], warnings: string[], opts: Options): Promise<void> {
  const actionable = findings.filter((f) => !isRemoteHeader(f.kind));
  let applied: MigrationResult | undefined;
  if (opts.apply && findings.length > 0) {
    applied =
      actionable.length > 0
        ? await withDaemon((client) => applyMigration(findings, client))
        : { migrated: 0, listedForPhase2: findings.length, backups: [], reformatted: [] };
  }

  if (opts.json) {
    say(
      JSON.stringify(
        {
          dryRun: !opts.apply,
          counts: countsByKind(findings),
          findings: findings.map(describe),
          warnings,
          ...(applied && { applied }),
        },
        null,
        2,
      ),
    );
    return;
  }

  const printWarnings = () => {
    if (warnings.length === 0) return;
    say();
    say("warnings:");
    for (const w of warnings) say(`  ${w}`);
  };
  if (findings.length === 0) {
    say("no plaintext secrets found");
    printWarnings();
    return;
  }
  const counts = countsByKind(findings);
  for (const line of table([
    ["KIND", "FINDINGS"],
    ...Object.entries(counts).map(([kind, n]) => [kind, String(n)]),
    ["total", String(findings.length)],
  ])) {
    say(line);
  }
  say();
  for (const line of table(findings.map((f) => [f.file, f.locator, fingerprint(f.detection)]))) {
    say(line);
  }
  printWarnings();
  say();

  if (!applied) {
    say("dry run: nothing was written. Re-run with --apply to move these into the vault.");
    return;
  }
  say(`migrated ${applied.migrated} · listed for phase 2: ${applied.listedForPhase2}`);
  if (applied.listedForPhase2 > 0) {
    say("remote MCP headers are listed only; agent-vault does not change them yet");
  }
  if (applied.backups.length > 0) {
    say(
      "backups hold the original PLAINTEXT secrets; delete them once you have checked the result:",
    );
    for (const b of applied.backups) say(`  ${b}`);
  }
  for (const r of applied.reformatted) {
    say(`${path.basename(r.file)} was reformatted (backup: ${r.backup})`);
  }
  say("Quit Claude Code / Codex / OpenCode first; a running harness may rewrite its config.");
}

/** Collects what the scan skipped or could not handle, to print with the findings. */
const sources = (warnings: string[]) => ({
  home: os.homedir(),
  cwd: process.cwd(),
  ...(process.env.CODEX_HOME && { codexHome: process.env.CODEX_HOME }),
  warn: (message: string) => void warnings.push(message),
});

export function migrateCommand(program: Command): void {
  program
    .command("migrate")
    .description("find plaintext secrets in .env files and harness MCP configs; --apply moves them")
    .option("--apply", "store the secrets and rewrite the files (without it nothing is written)")
    .option("--json", "print the findings as JSON (fingerprints only)")
    .action(async (opts: Options) => {
      const warnings: string[] = [];
      await report(await findPlaintextSecrets(sources(warnings)), warnings, opts);
    });
}

export function importCommand(program: Command): void {
  program
    .command("import")
    .argument("<file>", "a dotenv file")
    .description("migrate one .env file (dry run unless --apply)")
    .option("--apply", "store the secrets and rewrite the file")
    .option("--json", "print the findings as JSON (fingerprints only)")
    .action(async (file: string, opts: Options) => {
      const abs = path.resolve(file);
      if (!isFile(abs)) throw new CliError(`${abs} is not a file`, 2);
      const warnings: string[] = [];
      await report(
        findInDotenv(abs, (m) => void warnings.push(m)),
        warnings,
        opts,
      );
    });
}

function isFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}
