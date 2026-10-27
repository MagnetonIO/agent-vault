import { createHash } from "node:crypto";

/** `<ruleId> len=<N> sha256:<first 8 hex>`. Safe to log: it does not contain the value. */
export function fingerprint(d: { ruleId: string; value: string }): string {
  const digest = createHash("sha256").update(d.value, "utf8").digest("hex").slice(0, 8);
  return `${d.ruleId} len=${d.value.length} sha256:${digest}`;
}
