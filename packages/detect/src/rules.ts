/** One raw match: where it starts in the scanned text, and its text. */
export type RawMatch = { index: number; text: string };

export type Rule = {
  id: string;
  namePrefix: string;
  /** Higher wins when matches overlap. Only `generic-high-entropy` sits below the rest. */
  priority: number;
  /**
   * The raw matches in `text`; overlaps are resolved later. Must run in linear time on any input:
   * no regex here may repeat over an unbounded run of chars, since V8 throws `RangeError` (stack
   * overflow) on a run of a few MiB, and a detector that throws lets the key through.
   */
  scan: (text: string) => Iterable<RawMatch>;
  /**
   * Narrows or rejects a raw match; `offset` is where the value starts inside the match.
   * `before` is the text just ahead of the match (for context checks such as data URIs).
   */
  refine?: (match: string, before: string) => { offset: number; value: string } | null;
};

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

// Character classes as ASCII lookup tables, so runs are measured by a plain loop.
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = UPPER.toLowerCase();
const DIGITS = "0123456789";
const ALNUM = UPPER + LOWER + DIGITS;

function charTable(chars: string): Uint8Array {
  const table = new Uint8Array(128);
  for (const ch of chars) table[ch.charCodeAt(0)] = 1;
  return table;
}

const ALNUM_T = charTable(ALNUM);
const URLSAFE_T = charTable(`${ALNUM}_-`); // [A-Za-z0-9_-]
const ALNUM_UNDERSCORE_T = charTable(`${ALNUM}_`);
const ALNUM_DASH_T = charTable(`${ALNUM}-`);
const BASE64_T = charTable(`${ALNUM}+/=`);
const GENERIC_T = charTable(`${ALNUM}_-+/=`);
const HEX_T = charTable(`${DIGITS}abcdefABCDEF`);
const UPPER_T = charTable(UPPER);
const LETTER_T = charTable(UPPER + LOWER);
const LOWER_T = charTable(LOWER);

const inTable = (table: Uint8Array, code: number): boolean => code < 128 && table[code] === 1;

/** Where the run of `table` chars that starts at `from` ends. */
function runEnd(text: string, from: number, table: Uint8Array): number {
  let i = from;
  while (i < text.length && inTable(table, text.charCodeAt(i))) i++;
  return i;
}

const allIn = (s: string, table: Uint8Array): boolean => runEnd(s, 0, table) === s.length;

// Keys never start in the middle of a word ("task-…" must not look like "sk-…").
const LEAD = "(?<![A-Za-z0-9])";

/** Every match of a regex that only ever matches a bounded number of chars. */
function bounded(pattern: RegExp): (text: string) => Iterable<RawMatch> {
  return function* (text) {
    for (const m of text.matchAll(pattern)) yield { index: m.index, text: m[0] };
  };
}

/**
 * `prefix` (a bounded regex) followed by at least `min` chars of `table`, taken greedily: the same
 * matches as `prefix[class]{min,}`, without a regex over the run.
 */
function prefixRun(
  prefix: string,
  table: Uint8Array,
  min: number,
): (text: string) => Iterable<RawMatch> {
  return function* (text) {
    const re = new RegExp(prefix, "g");
    for (let m = re.exec(text); m !== null; m = re.exec(text)) {
      const bodyStart = m.index + m[0].length;
      const end = runEnd(text, bodyStart, table);
      if (end - bodyStart >= min) {
        yield { index: m.index, text: text.slice(m.index, end) };
        re.lastIndex = end;
      } else re.lastIndex = m.index + 1;
    }
  };
}

const DOT = ".".charCodeAt(0);

/** `eyJ<seg>.eyJ<seg>.<seg>` with each `<seg>` a run of [A-Za-z0-9_-]. */
function* scanJwt(text: string): Iterable<RawMatch> {
  const re = new RegExp(`${LEAD}eyJ`, "g");
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    const i = m.index;
    const e1 = runEnd(text, i + 3, URLSAFE_T);
    const e2 = e1 > i + 3 && text.startsWith(".eyJ", e1) ? runEnd(text, e1 + 4, URLSAFE_T) : -1;
    const e3 = e2 > e1 + 4 && text.charCodeAt(e2) === DOT ? runEnd(text, e2 + 1, URLSAFE_T) : -1;
    if (e3 > e2 + 1) {
      yield { index: i, text: text.slice(i, e3) };
      re.lastIndex = e3;
    } else {
      // An `eyJ` inside the first segment has the same segment end, so it fails the same way.
      re.lastIndex = Math.max(i + 1, e1);
    }
  }
}

const CR = 13;
const LF = 10;
const BACKSLASH = 92;

/**
 * Length of the line break at `i`, or 0. A line break is a real CRLF/LF, or the JSON escapes
 * `\r\n` / `\n` written out as backslash + letter (GCP service-account files).
 */
function lineBreakAt(text: string, i: number): number {
  const c = text.charCodeAt(i);
  if (c === CR && text.charCodeAt(i + 1) === LF) return 2;
  if (c === LF) return 1;
  if (c === BACKSLASH) {
    if (text.startsWith("\\r\\n", i)) return 4;
    if (text.startsWith("\\n", i)) return 2;
  }
  return 0;
}

function skipBlanks(text: string, i: number): number {
  let p = i;
  while (text[p] === " " || text[p] === "\t") p++;
  return p;
}

const PEM_HEADERS = ["Proc-Type:", "DEK-Info:"];

/** End of the PEM body line that starts at `i` (a base64 or header line), or -1 if it is not one. */
function pemLineEnd(text: string, i: number): number {
  let p = skipBlanks(text, i);
  const header = PEM_HEADERS.find((h) => text.startsWith(h, p));
  if (header) {
    p += header.length;
    for (let c = text.charCodeAt(p); p < text.length; c = text.charCodeAt(++p)) {
      if (c === CR || c === LF || c === BACKSLASH) break;
    }
  } else {
    const end = runEnd(text, p, BASE64_T);
    if (end === p) return -1;
    p = end;
  }
  p = skipBlanks(text, p);
  return p === text.length || lineBreakAt(text, p) > 0 ? p : -1;
}

// The label between BEGIN/END and PRIVATE KEY is short ("RSA ", "ENCRYPTED "); 64 bounds it.
const PEM_BEGIN = /-----BEGIN [A-Z ]{0,64}PRIVATE KEY-----/g;
const PEM_END = /-----END [A-Z ]{0,64}PRIVATE KEY-----/y;

/**
 * BEGIN line, then base64 / `Proc-Type:` / `DEK-Info:` lines, then the END line if there is one.
 * A truncated key (no END) stops at the first blank or non-base64 line, so half a pasted key is
 * still caught without swallowing the prose after it.
 */
function* scanPem(text: string): Iterable<RawMatch> {
  const re = new RegExp(PEM_BEGIN.source, "g");
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    let end = m.index + m[0].length;
    for (let br = lineBreakAt(text, end); br > 0; br = lineBreakAt(text, end)) {
      const lineEnd = pemLineEnd(text, end + br);
      if (lineEnd < 0) break;
      end = lineEnd;
    }
    const br = lineBreakAt(text, end);
    if (br > 0) {
      const endLine = new RegExp(PEM_END.source, "y");
      endLine.lastIndex = skipBlanks(text, end + br);
      const found = endLine.exec(text);
      if (found) end = found.index + found[0].length;
    }
    yield { index: m.index, text: text.slice(m.index, end) };
    re.lastIndex = end;
  }
}

/** Every maximal run of [A-Za-z0-9_\-+/=] of at least GENERIC_MIN_LENGTH chars. */
function* scanGeneric(text: string): Iterable<RawMatch> {
  let i = 0;
  while (i < text.length) {
    if (!inTable(GENERIC_T, text.charCodeAt(i))) {
      i++;
      continue;
    }
    const end = runEnd(text, i, GENERIC_T);
    if (end - i >= GENERIC_MIN_LENGTH) yield { index: i, text: text.slice(i, end) };
    i = end;
  }
}

// Identifiers, paths and branch names are made of dictionary-ish words; random secrets are not.
// A "word" is a capitalised or lowercase run of 3+ letters, or a run of 4+ capitals. When words
// cover more than WORD_COVERAGE_MAX of the string it is prose-like, not a secret. Measured on
// random base64 this drops about 0.08% of 40-char secrets (0.9% at 32 chars, 0.007% at 64).
const WORD_COVERAGE_MAX = 0.65;

/** Share of `s` covered by words: the matches of `/[A-Z]?[a-z]{3,}|[A-Z]{4,}/g`, found by a loop. */
function wordCoverage(s: string): number {
  let covered = 0;
  let i = 0;
  while (i < s.length) {
    const upper = inTable(UPPER_T, s.charCodeAt(i));
    const lowerFrom = upper ? i + 1 : i;
    const lowerEnd = runEnd(s, lowerFrom, LOWER_T);
    if (lowerEnd - lowerFrom >= 3) {
      covered += lowerEnd - i;
      i = lowerEnd;
      continue;
    }
    const upperEnd = upper ? runEnd(s, i, UPPER_T) : i;
    if (upperEnd - i >= 4) {
      covered += upperEnd - i;
      i = upperEnd;
      continue;
    }
    i++;
  }
  return covered / s.length;
}

// `NAME=value` is one run for the scanner. Only split at `=` when what precedes it reads as a
// variable name (ENV_STYLE, ALLCAPS, or word-like), so a random string containing `=` stays whole.
// The names are checked by loops, not regexes, since a run can be megabytes long.
const UPPER_DIGIT_T = charTable(UPPER + DIGITS);
const UNDERSCORE = "_".charCodeAt(0);

/** `/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/`: ENV_STYLE with at least one `_`, never two in a row. */
function isEnvName(name: string): boolean {
  if (!inTable(UPPER_T, name.charCodeAt(0))) return false;
  let underscores = 0;
  let i = 0;
  while (i < name.length) {
    const end = runEnd(name, i, UPPER_DIGIT_T);
    if (end === i) return false; // empty segment: `__`, or `_` at the end
    if (end === name.length) return underscores > 0;
    if (name.charCodeAt(end) !== UNDERSCORE) return false;
    underscores++;
    i = end + 1;
  }
  return false;
}

/** `/^[A-Za-z][A-Za-z0-9_-]*$/` */
const isIdent = (name: string): boolean =>
  inTable(LETTER_T, name.charCodeAt(0)) && allIn(name, URLSAFE_T);

function isAssignmentName(prefix: string): boolean {
  let dashes = 0;
  while (prefix[dashes] === "-") dashes++;
  const name = prefix.slice(dashes);
  if (isEnvName(name) || (name.length >= 3 && allIn(name, UPPER_T))) return true;
  return isIdent(name) && wordCoverage(name) >= WORD_COVERAGE_MAX;
}

// Subresource-integrity / lockfile hashes are random base64 by design and not secrets.
const INTEGRITY = /^sha(?:1|256|384|512)-/;
const EQ = "=".charCodeAt(0);

function refineGeneric(match: string, before: string): { offset: number; value: string } | null {
  // Image and file payloads (`data:image/png;base64,<payload>`).
  if (before.endsWith("base64,")) return null;

  // A trailing `=` is base64 padding and stays in the value.
  let unpadded = match.length;
  while (unpadded > 0 && match.charCodeAt(unpadded - 1) === EQ) unpadded--;
  const eq = unpadded > 0 ? match.lastIndexOf("=", unpadded - 1) : -1;
  const offset = eq > 0 && isAssignmentName(match.slice(0, eq)) ? eq + 1 : 0;
  const value = match.slice(offset);

  if (value.length < GENERIC_MIN_LENGTH) return null;
  if (allIn(value, HEX_T) || (value.length === 36 && UUID.test(value)) || INTEGRITY.test(value))
    return null;
  // Real random secrets of this length mix letters and digits; paths and identifiers do not.
  if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) return null;
  if (wordCoverage(value) > WORD_COVERAGE_MAX) return null;
  if (shannonEntropy(value) <= ENTROPY_MIN_BITS) return null;
  return { offset, value };
}

function concat(
  ...scans: ((text: string) => Iterable<RawMatch>)[]
): (text: string) => Iterable<RawMatch> {
  return function* (text) {
    for (const scan of scans) yield* scan(text);
  };
}

export const RULES: readonly Rule[] = [
  { id: "pem", namePrefix: "pem/private-key", priority: 20, scan: scanPem },
  {
    id: "anthropic",
    namePrefix: "anthropic/api-key",
    priority: 10,
    scan: prefixRun(`${LEAD}sk-ant-`, URLSAFE_T, 20),
  },
  {
    id: "openai",
    namePrefix: "openai/api-key",
    priority: 10,
    // `sk-proj-…` needs no case of its own: `proj-` is inside the run's class.
    scan: prefixRun(`${LEAD}sk-(?!ant-)`, URLSAFE_T, 20),
  },
  {
    id: "github",
    namePrefix: "github/pat",
    priority: 10,
    // The fixed-length form must end at a token boundary; a longer run falls through to
    // `generic-high-entropy` so the whole token is still redacted, never a prefix of it.
    scan: concat(
      bounded(new RegExp(`${LEAD}gh[pousr]_[A-Za-z0-9]{36}(?![A-Za-z0-9_])`, "g")),
      prefixRun(`${LEAD}github_pat_`, ALNUM_UNDERSCORE_T, 50),
    ),
  },
  {
    id: "slack",
    namePrefix: "slack/token",
    priority: 10,
    scan: prefixRun(`${LEAD}xox[baprs]-`, ALNUM_DASH_T, 10),
  },
  {
    id: "aws-akid",
    namePrefix: "aws/access-key-id",
    priority: 10,
    scan: bounded(new RegExp(`${LEAD}AKIA[0-9A-Z]{16}(?![A-Za-z0-9])`, "g")),
  },
  {
    id: "apify",
    namePrefix: "apify/api-token",
    priority: 10,
    scan: prefixRun(`${LEAD}apify_api_`, ALNUM_T, 20),
  },
  { id: "jwt", namePrefix: "jwt/token", priority: 10, scan: scanJwt },
  {
    id: "generic-high-entropy",
    namePrefix: "secret/unnamed",
    priority: 0,
    scan: scanGeneric,
    refine: refineGeneric,
  },
];
