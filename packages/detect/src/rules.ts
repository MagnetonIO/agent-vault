export type Rule = {
  id: string;
  namePrefix: string;
  /** Higher wins when matches overlap. Only `generic-high-entropy` sits below the rest. */
  priority: number;
  /** Must carry the `g` flag. */
  pattern: RegExp;
  /**
   * Narrows or rejects a raw match; `offset` is where the value starts inside the match.
   * `before` is the text just ahead of the match (for context checks such as data URIs).
   */
  refine?: (match: string, before: string) => { offset: number; value: string } | null;
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

// A line break: real CRLF/LF, or the JSON escapes `\\r\\n` / `\\n` written out as backslash + letter.
const SEP = "(?:\\r?\\n|\\\\r\\\\n|\\\\n)";

// Identifiers, paths and branch names are made of dictionary-ish words; random secrets are not.
// A "word" is a capitalised or lowercase run of 3+ letters, or a run of 4+ capitals. When words
// cover more than WORD_COVERAGE_MAX of the string it is prose-like, not a secret. Measured on
// random base64 this drops about 0.08% of 40-char secrets (0.9% at 32 chars, 0.007% at 64).
const WORD = /[A-Z]?[a-z]{3,}|[A-Z]{4,}/g;
const WORD_COVERAGE_MAX = 0.65;

function wordCoverage(s: string): number {
  let covered = 0;
  for (const m of s.matchAll(WORD)) covered += m[0].length;
  return covered / s.length;
}

// `NAME=value` is one run for the regex. Only split at `=` when what precedes it reads as a
// variable name (ENV_STYLE, ALLCAPS, or word-like), so a random string containing `=` stays whole.
const ENV_NAME = /^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/;
const ALLCAPS_NAME = /^[A-Z]{3,}$/;
const IDENT = /^[A-Za-z][A-Za-z0-9_-]*$/;

function isAssignmentName(prefix: string): boolean {
  const name = prefix.replace(/^-+/, "");
  if (ENV_NAME.test(name) || ALLCAPS_NAME.test(name)) return true;
  return IDENT.test(name) && wordCoverage(name) >= WORD_COVERAGE_MAX;
}

// Subresource-integrity / lockfile hashes are random base64 by design and not secrets.
const INTEGRITY = /^sha(?:1|256|384|512)-/;

function refineGeneric(match: string, before: string): { offset: number; value: string } | null {
  // Image and file payloads (`data:image/png;base64,<payload>`).
  if (/base64,$/.test(before)) return null;

  // A trailing `=` is base64 padding and stays in the value.
  const eq = match.replace(/=+$/, "").lastIndexOf("=");
  const offset = eq > 0 && isAssignmentName(match.slice(0, eq)) ? eq + 1 : 0;
  const value = match.slice(offset);

  if (value.length < GENERIC_MIN_LENGTH) return null;
  if (HEX.test(value) || UUID.test(value) || INTEGRITY.test(value)) return null;
  // Real random secrets of this length mix letters and digits; paths and identifiers do not.
  if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) return null;
  if (wordCoverage(value) > WORD_COVERAGE_MAX) return null;
  if (shannonEntropy(value) <= ENTROPY_MIN_BITS) return null;
  return { offset, value };
}

export const RULES: readonly Rule[] = [
  {
    id: "pem",
    namePrefix: "pem/private-key",
    priority: 20,
    // BEGIN line, then base64 / `Proc-Type:` / `DEK-Info:` lines, then the END line if there
    // is one. A truncated key (no END) stops at the first blank or non-base64 line, so half
    // a pasted key is still caught without swallowing the prose after it. A line break is a real
    // newline or the two-character JSON escape `\n` / `\r\n` (GCP service-account files).
    pattern: new RegExp(
      "-----BEGIN [A-Z ]*PRIVATE KEY-----" +
        `(?:${SEP}[ \\t]*(?:[A-Za-z0-9+/=]+|(?:Proc-Type|DEK-Info):[^\\r\\n\\\\]*)[ \\t]*(?=${SEP}|$))*` +
        `(?:${SEP}[ \\t]*-----END [A-Z ]*PRIVATE KEY-----)?`,
      "g",
    ),
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
