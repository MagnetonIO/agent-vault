import type { AuditEvent } from "@agent-vault/core";
import type { Command } from "commander";
import { withDaemon } from "../context.js";
import { CliError } from "../errors.js";
import { say, table } from "../output.js";

type Verdict = { ok: true } | { ok: false; brokenAtSeq: number };

type AuditOptions = {
  verify?: boolean;
  secret?: string;
  since?: string;
  limit?: string;
  json?: boolean;
};

export function auditCommand(program: Command): void {
  program
    .command("audit")
    .description("show the audit log, or check that it has not been altered")
    .option("--verify", "check the log's hash chain; exits 1 if it is broken")
    .option("--secret <name>", "only events about this secret")
    .option("--since <iso>", "only events at or after this time")
    .option("--limit <n>", "at most n events (newest first)")
    .option("--json", "print JSON")
    .action(async (opts: AuditOptions) => {
      if (opts.verify) {
        const verdict = await withDaemon((client) => client.call<Verdict>("audit.verify"));
        if (opts.json) say(JSON.stringify(verdict));
        else
          say(
            verdict.ok ? "audit log ok" : `audit log broken · brokenAtSeq ${verdict.brokenAtSeq}`,
          );
        // The verdict is the output; the exit code says it failed.
        if (!verdict.ok) throw new CliError("audit verification failed");
        return;
      }
      let limit: number | undefined;
      if (opts.limit !== undefined) {
        limit = Number(opts.limit);
        if (!Number.isInteger(limit) || limit < 1)
          throw new CliError("--limit must be a positive integer", 2);
      }
      const events = await withDaemon((client) =>
        client.call<AuditEvent[]>("audit.query", {
          ...(opts.secret !== undefined && { secretName: opts.secret }),
          ...(opts.since !== undefined && { since: opts.since }),
          ...(limit !== undefined && { limit }),
        }),
      );
      if (opts.json) {
        say(JSON.stringify(events, null, 2));
        return;
      }
      if (events.length === 0) {
        say("no audit events");
        return;
      }
      const rows = events.map((e) => [
        e.ts,
        e.outcome,
        e.operation,
        e.secretName ?? "-",
        e.bundle === undefined ? "" : `bundle=${e.bundle}`,
        e.harness ?? "",
      ]);
      for (const line of table(rows)) say(line);
    });
}
