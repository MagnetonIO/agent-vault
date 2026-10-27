#!/usr/bin/env node
// Spike S3: SessionEnd hook that scrubs AVCANARY_<uuid> from transcript_path (temp file + rename) while Claude Code is still alive.
import {
  appendFileSync,
  existsSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from "node:fs";

const CANARY = /AVCANARY_[0-9a-f-]{36}/g;
const log = (o) =>
  process.env.AV_HOOK_LOG && appendFileSync(process.env.AV_HOOK_LOG, `${JSON.stringify(o)}\n`);
let input = {};
try {
  input = JSON.parse(readFileSync(0, "utf8"));
} catch {}
const f = input.transcript_path;
if (input.hook_event_name !== "SessionEnd" || !f || !existsSync(f)) {
  log({ at: "scrub-hook", event: input.hook_event_name, skipped: true });
} else {
  const before = readFileSync(f, "utf8");
  const hits = (before.match(CANARY) ?? []).length;
  const tmp = `${f}.scrub-${process.pid}.tmp`;
  writeFileSync(tmp, before.replace(CANARY, "[REDACTED:vault]"), {
    mode: statSync(f).mode & 0o777,
  });
  renameSync(tmp, f);
  log({
    at: "scrub-hook",
    event: "SessionEnd",
    hitsBefore: hits,
    hitsAfter: (readFileSync(f, "utf8").match(CANARY) ?? []).length,
  });
}
