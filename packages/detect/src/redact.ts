export type Redactor = {
  push(chunk: string): string;
  flush(): string;
  /** How many chars are held back right now; at most about twice the longest variant (three times for base64, which may hold line breaks). */
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

/** Fewest chars of base64 that depend on the key alone for an offset variant to be worth using. */
const MIN_OFFSET_CHARS = 12;
const BASE64_ENCODINGS = ["base64", "base64url"] as const;

/**
 * The base64 and base64url texts a secret leaves in a larger encoded buffer. The encoding of a
 * byte string depends on where it starts: `k` = 0, 1 or 2 bytes after a 3-byte boundary shifts every
 * 6-bit group. For each of those offsets the characters made of key bits only are kept: not
 * the leading ones that also hold bits of the `k` bytes before it, nor the trailing ones that also
 * hold bits of the bytes after it. That is a substring of every encoding of a buffer that holds
 * the key at that alignment, whatever else is in the buffer. Where the key is the end of the data,
 * the last partial character and the padding are key-only too, so that form is kept as well.
 * A form with under MIN_OFFSET_CHARS key-only chars is dropped; it would hit ordinary text.
 */
function base64OffsetForms(bytes: Buffer): string[] {
  const forms: string[] = [];
  for (const encoding of BASE64_ENCODINGS) {
    for (let k = 0; k < 3; k++) {
      const first = Math.ceil((8 * k) / 6);
      const end = Math.floor((8 * (k + bytes.length)) / 6);
      if (end - first < MIN_OFFSET_CHARS) continue;
      const lead = Buffer.alloc(k);
      // Zero filler: the chars kept never depend on it, which the tests check with other fillers.
      const inside = Buffer.concat([lead, bytes, Buffer.alloc(2)]).toString(encoding);
      forms.push(inside.slice(first, end));
      forms.push(Buffer.concat([lead, bytes]).toString(encoding).slice(first));
    }
  }
  return forms;
}

/**
 * Every form one secret is likely to be printed in. `plain` forms are matched as they are: raw;
 * URI-component with upper- and lowercase `%xx`; and the inside of a JSON string literal (what
 * `JSON.stringify` prints for a value with quotes, backslashes or control characters); also
 * standard base64 wrapped at 64 and 76 columns with LF or CRLF. Any form that contains a control
 * character (the wrapped base64 ones) is also listed in that escaped form, since that is how a
 * JSON transcript stores a multi-line copy.
 *
 * `base64` forms are standard base64 and base64url (no padding), and the same for the secret
 * starting 1 or 2 bytes into a 3-byte group (see `base64OffsetForms`). They are matched ignoring
 * line breaks, so they also cover a wrap at any column, whatever sits in front of the secret.
 */
function variantsOf(value: string): { plain: string[]; base64: string[] } {
  // A short value still shows up escaped when it holds a quote, a backslash or a control char.
  if (value.length < MIN_ENCODED_LENGTH)
    return { plain: [...new Set([value, JSON.stringify(value).slice(1, -1)])], base64: [] };
  const bytes = Buffer.from(value, "utf8");
  const base64 = bytes.toString("base64");
  const urlencoded = encodeURIComponent(value);
  const forms = [
    value,
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
  return {
    plain: [...new Set([...forms, ...escaped])],
    base64: [...new Set([base64, bytes.toString("base64url"), ...base64OffsetForms(bytes)])],
  };
}

/** Every text `value` is redacted in (see `variantsOf`). The scrubber uses them to pre-screen text. */
export const secretForms = (value: string): string[] => {
  const { plain, base64 } = variantsOf(value);
  return [...plain, ...base64];
};

/** `text` with its line breaks (`\r?\n`) taken out, and how to find a char's place in the original. */
type Stripped = { text: string; at: (index: number) => number };

/** With `dropTrailingCr`, a `\r` that ends the text goes too: it may be half of a `\r\n`. */
function stripBreaks(text: string, dropTrailingCr = false): Stripped {
  const segStart: number[] = [0];
  const segOffset: number[] = [0];
  const parts: string[] = [];
  let last = 0;
  let length = 0;
  for (const m of text.matchAll(dropTrailingCr ? /\r?\n|\r$/g : /\r?\n/g)) {
    const index = m.index as number;
    parts.push(text.slice(last, index));
    length += index - last;
    last = index + m[0].length;
    segStart.push(last);
    segOffset.push(length);
  }
  if (last === 0) return { text, at: (index) => index };
  parts.push(text.slice(last));
  return {
    text: parts.join(""),
    at(index) {
      let lo = 0;
      let hi = segOffset.length - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if ((segOffset[mid] as number) <= index) lo = mid;
        else hi = mid - 1;
      }
      return (segStart[lo] as number) + index - (segOffset[lo] as number);
    },
  };
}

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
  const base64Variants = new Map<string, string>();
  for (const s of secrets) {
    if (s.value.length < MIN_SECRET_LENGTH) {
      throw new RangeError(
        `secret "${s.name}" is shorter than ${MIN_SECRET_LENGTH} characters and cannot be redacted safely`,
      );
    }
    const forms = variantsOf(s.value);
    for (const text of forms.plain) if (!variants.has(text)) variants.set(text, s.name);
    for (const text of forms.base64)
      if (!base64Variants.has(text)) base64Variants.set(text, s.name);
  }
  const texts = [...variants.keys()];
  const firstChars = new Set(texts.map((t) => t[0]));
  const base64Texts = [...base64Variants.keys()];
  const base64FirstChars = new Set(base64Texts.map((t) => t[0]));
  const base64Longest = Math.max(1, ...base64Texts.map((t) => t.length));
  /** A held base64 prefix has at most a `\r\n` after each char, and maybe a lone `\r` at the end. */
  const base64Window = 3 * base64Longest + 2;
  const plainLongest = Math.max(1, ...texts.map((t) => t.length));
  const longest = Math.max(plainLongest, base64Longest);
  let held = "";
  /** How many chars at the start of `held` were already redacted (see `drain`). */
  let covered = 0;

  /** Length of the longest suffix of `buf` that is a proper prefix of some plain variant. */
  function plainHeldLength(buf: string): number {
    for (let i = Math.max(0, buf.length - (plainLongest - 1)); i < buf.length; i++) {
      if (!firstChars.has(buf[i])) continue;
      const tail = buf.slice(i);
      if (texts.some((t) => t.length > tail.length && t.startsWith(tail))) return tail.length;
    }
    return 0;
  }

  /**
   * Length of the longest suffix of `buf` that is, with its line breaks taken out, a proper prefix
   * of some base64 variant. Line breaks inside it are held too, so this can reach 3 chars per char.
   */
  function base64HeldLength(buf: string): number {
    const base = Math.max(0, buf.length - base64Window);
    const { text, at } = stripBreaks(buf.slice(base), true);
    for (let i = Math.max(0, text.length - (base64Longest - 1)); i < text.length; i++) {
      if (!base64FirstChars.has(text[i])) continue;
      const tail = text.slice(i);
      if (base64Texts.some((t) => t.length > tail.length && t.startsWith(tail))) {
        return buf.length - (base + at(i));
      }
    }
    return 0;
  }

  const heldSuffixLength = (buf: string): number =>
    Math.max(plainHeldLength(buf), base64HeldLength(buf));

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
    // Base64 is matched with its line breaks taken out, so a wrapped copy matches at any column.
    const { text: flat, at } = stripBreaks(buf);
    for (const [text, name] of base64Variants) {
      for (let i = flat.indexOf(text); i !== -1; i = flat.indexOf(text, i + 1)) {
        const end = at(i + text.length - 1) + 1;
        if (end > covered) found.push({ start: at(i), end, name });
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
