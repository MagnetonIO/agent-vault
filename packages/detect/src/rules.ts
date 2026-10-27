export type Rule = {
  id: string;
  namePrefix: string;
  /** Higher wins when matches overlap. Only `generic-high-entropy` sits below the rest. */
  priority: number;
  /** Must carry the `g` flag. */
  pattern: RegExp;
  /** Narrows or rejects a raw match; `offset` is where the value starts inside the match. */
  refine?: (match: string) => { offset: number; value: string } | null;
};

const HEX = /^[0-9a-fA-F]+$/;
const UUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const ENTROPY_MIN_BITS = 4.3;
const GENERIC_MIN_LENGTH = 32;

export function shannonEntropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let total = 0;
  for (const n of counts.values()) total += n;
  let h = 0;
  for (const n of counts.values()) {
    const p = n / total;
    h -= p * Math.log2(p);
  }
  return h;
}

// Keys never start in the middle of a word ("task-…" must not look like "sk-…").
const LEAD = "(?<![A-Za-z0-9])";

function refineGeneric(match: string): { offset: number; value: string } | null {
  // `NAME=value` is one run for the regex; the secret is only the part after the last
  // interior `=` (a trailing `=` is base64 padding and stays).
  const body = match.replace(/=+$/, "");
  const offset = body.lastIndexOf("=") + 1;
  const value = match.slice(offset);
  if (value.length < GENERIC_MIN_LENGTH) return null;
  if (HEX.test(value) || UUID.test(value)) return null;
  // Real random secrets of this length mix letters and digits; paths and identifiers do not.
  if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) return null;
  if (shannonEntropy(value) <= ENTROPY_MIN_BITS) return null;
  return { offset, value };
}

export const RULES: readonly Rule[] = [
  {
    id: "pem",
    namePrefix: "pem/private-key",
    priority: 20,
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  },
  {
    id: "anthropic",
    namePrefix: "anthropic/api-key",
    priority: 10,
    pattern: new RegExp(`${LEAD}sk-ant-[A-Za-z0-9_-]{20,}`, "g"),
  },
  {
    id: "openai",
    namePrefix: "openai/api-key",
    priority: 10,
    pattern: new RegExp(`${LEAD}sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}`, "g"),
  },
  {
    id: "github",
    namePrefix: "github/pat",
    priority: 10,
    // The fixed-length form must end at a token boundary; a longer run falls through to
    // `generic-high-entropy` so the whole token is still redacted, never a prefix of it.
    pattern: new RegExp(
      `${LEAD}(?:gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9_])|github_pat_[A-Za-z0-9_]{50,})`,
      "g",
    ),
  },
  {
    id: "slack",
    namePrefix: "slack/token",
    priority: 10,
    pattern: new RegExp(`${LEAD}xox[baprs]-[A-Za-z0-9-]{10,}`, "g"),
  },
  {
    id: "aws-akid",
    namePrefix: "aws/access-key-id",
    priority: 10,
    pattern: new RegExp(`${LEAD}AKIA[0-9A-Z]{16}(?![A-Za-z0-9])`, "g"),
  },
  {
    id: "apify",
    namePrefix: "apify/api-token",
    priority: 10,
    pattern: new RegExp(`${LEAD}apify_api_[A-Za-z0-9]{20,}`, "g"),
  },
  {
    id: "jwt",
    namePrefix: "jwt/token",
    priority: 10,
    pattern: new RegExp(`${LEAD}eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+`, "g"),
  },
  {
    id: "generic-high-entropy",
    namePrefix: "secret/unnamed",
    priority: 0,
    pattern: /[A-Za-z0-9_\-+/=]{32,}/g,
    refine: refineGeneric,
  },
];
