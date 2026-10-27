// Where the value sits on one `.env` line. Mirrors the parsing in core's `parseEnvFile`, which
// reports a value but not its position, and which keeps an unclosed quote's rest-of-line.

export const ENV_LINE_RE = /^(﻿?\s*(?:export\s+)?)([^=]*?)(\s*=\s*)(.*)$/s;

/** The index of the quote that closes the one at `s[0]`, or -1. */
export function closingQuote(s: string): number {
  const quote = s[0];
  for (let i = 1; i < s.length; i++) {
    if (quote === '"' && s[i] === "\\") i++;
    else if (s[i] === quote) return i;
  }
  return -1;
}

export type EnvLine = {
  /** Leading space and `export `. */
  head: string;
  key: string;
  /** Spacing, `=` and spacing. */
  eq: string;
  /** Everything after the `=` and its spacing. */
  rest: string;
  quote: '"' | "'" | null;
  /** The value token is `rest.slice(start, end)`; for a quoted value, without the quotes. */
  start: number;
  end: number;
  /** An opening quote that does not close on this line: the value goes on to later lines. */
  unclosed: boolean;
};

export function splitEnvLine(line: string): EnvLine | null {
  const m = ENV_LINE_RE.exec(line);
  if (!m) return null;
  const [, head = "", key = "", eq = "", rest = ""] = m;
  const q = rest[0];
  if (q === '"' || q === "'") {
    const close = closingQuote(rest);
    return {
      head,
      key,
      eq,
      rest,
      quote: q,
      start: 1,
      end: close === -1 ? rest.length : close,
      unclosed: close === -1,
    };
  }
  const comment = /\s#/.exec(rest);
  const end = (comment ? rest.slice(0, comment.index) : rest).trimEnd().length;
  return { head, key, eq, rest, quote: null, start: 0, end, unclosed: false };
}
