export type Redactor = {
  push(chunk: string): string;
  flush(): string;
};

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
 * quotes, backslashes or control characters).
 */
function variantsOf(value: string): string[] {
  if (value.length < MIN_ENCODED_LENGTH) return [value];
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
  return [...new Set(forms)];
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
 * is held whole until the next push, since more data could still extend it.
 *
 * Throws `RangeError` (naming the secret, never its value) for values under 4 chars.
 */
export function createRedactor(secrets: { name: string; value: string }[]): Redactor {
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

  /** Length of the longest suffix of `buf` that is a proper prefix of some variant. */
  function heldSuffixLength(buf: string): number {
    for (let i = Math.max(0, buf.length - (longest - 1)); i < buf.length; i++) {
      if (!firstChars.has(buf[i])) continue;
      const tail = buf.slice(i);
      if (texts.some((t) => t.length > tail.length && t.startsWith(tail))) return tail.length;
    }
    return 0;
  }

  /** Every complete match in `buf`, with overlapping or adjacent ones merged. */
  function mergedMatches(buf: string): Span[] {
    const found: Span[] = [];
    for (const [text, name] of variants) {
      for (let i = buf.indexOf(text); i !== -1; i = buf.indexOf(text, i + 1)) {
        found.push({ start: i, end: i + text.length, name });
      }
    }
    found.sort((a, b) => a.start - b.start || b.end - a.end);
    const merged: Span[] = [];
    for (const m of found) {
      const last = merged[merged.length - 1];
      if (last && m.start <= last.end) last.end = Math.max(last.end, m.end);
      else merged.push({ ...m });
    }
    return merged;
  }

  function drain(buf: string, limit: number, final: boolean): { out: string; rest: string } {
    let out = "";
    let cursor = 0;
    let emitUpTo = final ? buf.length : limit;
    for (const m of mergedMatches(buf)) {
      // A span that reaches `limit` could still grow (or merge with a match that is only
      // partly buffered), so it and everything after it waits for more data.
      if (!final && m.end >= limit) {
        emitUpTo = Math.min(m.start, limit);
        break;
      }
      out += `${buf.slice(cursor, m.start)}[redacted vault://${m.name}]`;
      cursor = m.end;
    }
    return { out: out + buf.slice(cursor, emitUpTo), rest: buf.slice(emitUpTo) };
  }

  return {
    push(chunk) {
      const buf = held + chunk;
      let limit = buf.length - heldSuffixLength(buf);
      // Never emit half of a surrogate pair.
      if (limit > 0 && limit < buf.length && isHighSurrogate(buf.charCodeAt(limit - 1))) limit--;
      const { out, rest } = drain(buf, limit, false);
      held = rest;
      return out;
    },
    flush() {
      const { out } = drain(held, held.length, true);
      held = "";
      return out;
    },
  };
}
