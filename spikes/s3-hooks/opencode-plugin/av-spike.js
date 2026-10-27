// Spike S3: OpenCode v2.1.4 plugin (default export {id, setup}). Registers every hook name found in the binary
// (ctx.<domain>.hook(name, cb)), logs invocations and draft shapes, and with AV_OC_MODE can redact/reject AVCANARY_ in
// session.context / session.model.request drafts.
import { appendFileSync } from "node:fs";

const log = (o) =>
  process.env.AV_HOOK_LOG && appendFileSync(process.env.AV_HOOK_LOG, `${JSON.stringify(o)}\n`);
const CANARY = /AVCANARY_[0-9a-f-]+/g;
const shape = (v, d = 0) =>
  v === null || v === undefined
    ? String(v)
    : Array.isArray(v)
      ? `array(${v.length})${v.length && d < 3 ? `<${shape(v[0], d + 1)}>` : ""}`
      : typeof v === "object"
        ? d < 3
          ? "{" +
            Object.entries(v)
              .map(([k, x]) => `${k}:${shape(x, d + 1)}`)
              .join(",") +
            "}"
          : "object"
        : typeof v;
const redactDeep = (v) =>
  typeof v === "string"
    ? v.replace(CANARY, "[REDACTED:vault]")
    : Array.isArray(v)
      ? v.map(redactDeep)
      : v && typeof v === "object"
        ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, redactDeep(x)]))
        : v;
const mode = () => process.env.AV_OC_MODE ?? "log";
const NAMES = {
  session: [
    "compaction",
    "context",
    "generate",
    "http.request",
    "http.response",
    "model.request",
    "retry",
    "title",
  ],
  aisdk: ["sdk", "language"],
  tool: ["execute.before", "execute.after"],
  shell: ["env", "before", "after", "execute.before"],
  permission: ["evaluate"],
};
export default {
  id: "av-spike",
  async setup(ctx) {
    for (const [domain, names] of Object.entries(NAMES)) {
      for (const name of names) {
        try {
          await ctx[domain].hook(name, (draft) => {
            let hasCanary = false;
            try {
              hasCanary = JSON.stringify(draft, (_k, v) =>
                typeof v === "function" ? undefined : v,
              ).includes("AVCANARY_");
            } catch {}
            log({ hook: `${domain}.${name}`, hasCanary, shape: shape(draft) });
            if (
              hasCanary &&
              domain === "session" &&
              mode() === "mutate" &&
              (name === "context" || name === "title")
            ) {
              for (const [k, v] of Object.entries(draft)) {
                try {
                  draft[k] = redactDeep(v);
                } catch (e) {
                  log({ mutateError: String(e), key: k });
                }
              }
              log({ hook: `${domain}.${name}`, mutated: true });
            }
            if (hasCanary && mode() === `throw-${name}`)
              throw new Error("agent-vault spike: canary detected, rejected");
          });
          log({ registered: `${domain}.${name}` });
        } catch (e) {
          log({ registerFailed: `${domain}.${name}`, err: String(e).slice(0, 200) });
        }
      }
    }
  },
};
