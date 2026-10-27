export type Redactor = {
  push(chunk: string): string;
  flush(): string;
  /** How many chars are held back right now; at most about twice the longest variant. */
  heldLength(): number;
  /** How many redactions have been emitted so far (a merged run of matches counts once). */
  matchCount(): number;
};

export type RedactorOptions = {
  /** The text that replaces a match of the secret called `name`. Defaults to `[redacted vault://<name>]`. */
  marker?: (name: string) => string;
};

const defaultMarker = (name: string): string => `[redacted vault://${name}]`;

type Span = { start: number; end: number; name: string };

/** Values under this length cannot be redacted without mangling ordinary text. */
const MIN_SECRET_LENGTH = 4;
/** Shorter values are redacted in raw form only; encoded forms of tiny strings are noise. */
const MIN_ENCODED_LENGTH = 8;

/** Columns at which `openssl base64` (64) and GNU `base64`, MIME and PEM (76) wrap their lines. */
const WRAP_COLUMNS = [64, 76] as const;
const LINE_BREAKS = ["\n", "\r\n"] as const;

const wrap = (text: string, columns: number, lineBreak: string): string => {
  const lines: string[] = [];
  for (let i = 0; i < text.length; i += columns) lines.push(text.slice(i, i + columns));
  return lines.join(lineBreak);
};

/**
 * Every form one secret is likely to be printed in: raw; standard base64, also wrapped at 64 and
 * 76 columns with LF or CRLF; base64url (no padding); URI-component with upper- and lowercase
 * `%xx`; and the inside of a JSON string literal (what `JSON.stringify` prints for a value with
 * quotes, backslashes or control characters). Any form that contains a control character (the
 * wrapped base64 ones) is also listed in that escaped form, since that is how a JSON transcript
 * stores a multi-line copy.
 */
function variantsOf(value: string): string[] {
  // A short value still shows up escaped when it holds a quote, a backslash or a control char.
  if (value.length < MIN_ENCODED_LENGTH)
    return [...new Set([value, JSON.stringify(value).slice(1, -1)])];
  const bytes = Buffer.from(value, "utf8");
  const base64 = bytes.toString("base64");
  const urlencoded = encodeURIComponent(value);
  const forms = [
    value,
    base64,
    bytes.toString("base64url"),
    urlencoded,
    urlencoded.replace(/%[0-9A-F]{2}/g, (hex) => hex.toLowerCase()),
    JSON.stringify(value).slice(1, -1),
    ...WRAP_COLUMNS.flatMap((columns) =>
      LINE_BREAKS.map((lineBreak) => wrap(base64, columns, lineBreak)),
    ),
  ];
  const escaped = forms
    .filter((form) => /\p{Cc}/u.test(form))
    .map((form) => JSON.stringify(form).slice(1, -1));
  return [...new Set([...forms, ...escaped])];
}

/** Every text `value` is redacted in (see `variantsOf`). The scrubber uses them to pre-screen text. */
export const secretForms = variantsOf;

const isHighSurrogate = (code: number) => code >= 0xd800 && code <= 0xdbff;

/**
 * Streaming redactor. Between pushes it holds back only the longest suffix of the buffer that is a
 * proper prefix of some variant (the only text a later chunk could complete into a match), so
 * ordinary output such as a prompt is released at once; `flush()` releases whatever is held. There
 * is deliberately no timer: flushing a held suffix early could leak most of a secret.
 *
 * Matches that overlap or touch are merged into one redaction named after the leftmost match,
 * so no tail of an overlapping secret survives. A merged run that reaches the hold-back window
 * is held until the next push, since more data could still extend it; once such a run is longer
 * than the longest variant its finished part is redacted at once (as one redaction per push), so
 * the work and the memory stay linear however long the run is.
 *
 * Throws `RangeError` (naming the secret, never its value) for values under 4 chars.
 */
export function createRedactor(
  secrets: { name: string; value: string }[],
  opts: RedactorOptions = {},
): Redactor {
  const marker = opts.marker ?? defaultMarker;
  let emitted = 0;
  const variants = new Map<string, string>();
  for (const s of secrets) {
    if (s.value.length < MIN_SECRET_LENGTH) {
      throw new RangeError(
        `secret "${s.name}" is shorter than ${MIN_SECRET_LENGTH} characters and cannot be redacted safely`,
      );
    }
    for (const text of variantsOf(s.value)) {
      if (!variants.has(text)) variants.set(text, s.name);
    }
  }
  const texts = [...variants.keys()];
  const firstChars = new Set(texts.map((t) => t[0]));
  const longest = Math.max(1, ...texts.map((t) => t.length));
  let held = "";
  /** How many chars at the start of `held` were already redacted (see `drain`). */
  let covered = 0;

  /** Length of the longest suffix of `buf` that is a proper prefix of some variant. */
  function heldSuffixLength(buf: string): number {
    for (let i = Math.max(0, buf.length - (longest - 1)); i < buf.length; i++) {
      if (!firstChars.has(buf[i])) continue;
      const tail = buf.slice(i);
      if (texts.some((t) => t.length > tail.length && t.startsWith(tail))) return tail.length;
    }
    return 0;
  }

  /**
   * Every complete match in `buf`, sorted by start. Matches that end inside the first `covered`
   * chars are skipped: a redaction was already sent for those chars.
   */
  function matchesIn(buf: string, covered: number): Span[] {
    const found: Span[] = [];
    for (const [text, name] of variants) {
      for (let i = buf.indexOf(text); i !== -1; i = buf.indexOf(text, i + 1)) {
        if (i + text.length > covered) found.push({ start: i, end: i + text.length, name });
      }
    }
    return found.sort((a, b) => a.start - b.start || b.end - a.end);
  }

  /** Overlapping or adjacent matches merged into spans, each named after its leftmost match. */
  function mergeSpans(found: Span[]): Span[] {
    const merged: Span[] = [];
    for (const m of found) {
      const last = merged[merged.length - 1];
      if (last && m.start <= last.end) last.end = Math.max(last.end, m.end);
      else merged.push({ ...m });
    }
    return merged;
  }

  /**
   * Redact `buf`, whose first `covered` chars already have their redaction sent. Returns what can
   * be sent now, what stays held and how many chars at the start of that are covered.
   */
  function drain(
    buf: string,
    covered: number,
    limit: number,
    final: boolean,
  ): { out: string; rest: string; covered: number } {
    const found = matchesIn(buf, covered);
    let out = "";
    let cursor = covered;
    let coverEnd = covered;
    let emitUpTo = final ? buf.length : limit;
    for (const m of mergeSpans(found)) {
      // A span that reaches `limit` could still grow (or merge with a match that is only
      // partly buffered), so it and everything after it waits for more data.
      if (!final && m.end >= limit) {
        if (limit - m.start > longest) {
          // A run this long (a secret printed over and over) must not be held whole and rescanned
          // on every push. Everything before `limit` is covered by whole matches, so redact it
          // now. A match that begins before `limit` and ends after it is redacted too: its end
          // is remembered as `covered` so it is dropped, never printed, when the tail is sent.
          out += buf.slice(cursor, m.start) + marker(m.name);
          emitted++;
          cursor = limit;
          for (const f of found) {
            if (f.start >= m.start && f.start < limit) coverEnd = Math.max(coverEnd, f.end);
          }
        } else {
          emitUpTo = Math.min(m.start, limit);
        }
        break;
      }
      out += buf.slice(cursor, m.start) + marker(m.name);
      emitted++;
      cursor = m.end;
    }
    return {
      out: out + buf.slice(cursor, emitUpTo),
      rest: buf.slice(emitUpTo),
      covered: Math.max(0, coverEnd - emitUpTo),
    };
  }

  return {
    push(chunk) {
      const buf = held + chunk;
      let limit = buf.length - heldSuffixLength(buf);
      // Never emit half of a surrogate pair.
      if (limit > 0 && limit < buf.length && isHighSurrogate(buf.charCodeAt(limit - 1))) limit--;
      const result = drain(buf, covered, limit, false);
      held = result.rest;
      covered = result.covered;
      return result.out;
    },
    flush() {
      const { out } = drain(held, covered, held.length, true);
      held = "";
      covered = 0;
      return out;
    },
    heldLength: () => held.length,
    matchCount: () => emitted,
  };
}
