#!/usr/bin/env node
// Spike S3: Claude Code UserPromptSubmit hook. Logs raw stdin, blocks prompts containing AVCANARY_.
import { appendFileSync, existsSync, readFileSync } from "node:fs";

const log = process.env.AV_HOOK_LOG;
const raw = readFileSync(0, "utf8");
if (log) appendFileSync(log, `${JSON.stringify({ at: "stdin", raw })}\n`);
let input = {};
try {
  input = JSON.parse(raw);
} catch {}
const out = (input.prompt ?? "").includes("AVCANARY_")
  ? {
      decision: "block",
      reason: "agent-vault spike: canary detected and stored (fake). Key not sent to model.",
      hookSpecificOutput: {
        hookEventName: "UserPromptSubmit",
        ...(process.env.AV_NO_SUPPRESS ? {} : { suppressOriginalPrompt: true }),
      },
    }
  : {};
const s = JSON.stringify(out);
// Is the canary already in the transcript when the hook runs? (decides whether the hook can scrub inline)
if (log && input.transcript_path) {
  const exists = existsSync(input.transcript_path);
  const has = exists && readFileSync(input.transcript_path, "utf8").includes("AVCANARY_");
  appendFileSync(
    log,
    `${JSON.stringify({ at: "transcript-at-hook-time", exists, hasCanary: has })}\n`,
  );
}
if (log) appendFileSync(log, `${JSON.stringify({ at: "stdout", raw: s })}\n`);
process.stdout.write(s);
