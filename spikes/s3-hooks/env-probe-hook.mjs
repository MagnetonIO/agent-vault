#!/usr/bin/env node
// Spike S3 step 4 proxy: counts AVCANARY_ occurrences in the hook's own env (hooks are child processes like Bash tool).
import { appendFileSync, readFileSync } from "node:fs";

const raw = readFileSync(0, "utf8");
let ev = "";
try {
  ev = JSON.parse(raw).hook_event_name;
} catch {}
const hits = Object.entries(process.env)
  .filter(([_k, v]) => String(v).includes("AVCANARY_"))
  .map(([k]) => k);
appendFileSync(
  process.env.AV_ENV_LOG,
  `${JSON.stringify({
    event: ev,
    count: hits.length,
    keys: hits,
    anthropicApiKeySet: "ANTHROPIC_API_KEY" in process.env,
  })}\n`,
);
