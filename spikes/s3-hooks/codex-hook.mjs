#!/usr/bin/env node
// Spike S3: Codex hook. Logs raw stdin, blocks UserPromptSubmit prompts containing AVCANARY_.
import { appendFileSync, existsSync, readFileSync } from "node:fs";

const log = process.env.AV_HOOK_LOG;
const raw = readFileSync(0, "utf8");
if (log) appendFileSync(log, `${JSON.stringify({ at: "stdin", raw })}\n`);
let input = {};
try {
  input = JSON.parse(raw);
} catch {}
const blocked =
  input.hook_event_name === "UserPromptSubmit" && (input.prompt ?? "").includes("AVCANARY_");
const out = blocked
  ? {
      decision: "block",
      reason: "agent-vault spike: canary detected and stored (fake). Key not sent to model.",
    }
  : {};
const s = JSON.stringify(out);
if (log) {
  appendFileSync(log, `${JSON.stringify({ at: "stdout", raw: s })}\n`);
  if (input.transcript_path) {
    const exists = existsSync(input.transcript_path);
    appendFileSync(
      log,
      `${JSON.stringify({
        at: "transcript-at-hook-time",
        event: input.hook_event_name,
        exists,
        hasCanary: exists && readFileSync(input.transcript_path, "utf8").includes("AVCANARY_"),
      })}\n`,
    );
  }
}
process.stdout.write(s);
