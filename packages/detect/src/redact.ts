export type Redactor = {
  push(chunk: string): string;
  flush(): string;
};

type Span = { start: number; end: number; name: string };

/** Values under this length cannot be redacted without mangling ordinary text. */
const MIN_SECRET_LENGTH = 4;
/** Shorter values are redacted in raw form only; encoded forms of tiny strings are noise. */
const MIN_ENCODED_LENGTH = 8;

/** Raw, standard base64, base64url (no padding) and URI-component forms of one secret. */
function variantsOf(value: string): string[] {
  if (value.length < MIN_ENCODED_LENGTH) return [value];
  const bytes = Buffer.from(value, "utf8");
  const forms = [
    value,
    bytes.toString("base64"),
    bytes.toString("base64url"),
    encodeURIComponent(value),
  ];
  return [...new Set(forms)];
}

const isHighSurrogate = (code: number) => code >= 0xd800 && code <= 0xdbff;

/**
 * Streaming redactor. Between pushes it holds back `maxVariantLength - 1` chars so a secret
 * split across chunks is still matched; `flush()` releases whatever is held.
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
  const holdBack = Math.max(1, ...[...variants.keys()].map((t) => t.length)) - 1;
  let held = "";

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
      let limit = Math.max(0, buf.length - holdBack);
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
