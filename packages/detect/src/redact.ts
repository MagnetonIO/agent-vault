export type Redactor = {
  push(chunk: string): string;
  flush(): string;
};

type Variant = { text: string; name: string };

/** Raw, standard base64, base64url (no padding) and URI-component forms of one secret. */
function variantsOf(value: string): string[] {
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
 */
export function createRedactor(secrets: { name: string; value: string }[]): Redactor {
  const variants = new Map<string, Variant>();
  for (const s of secrets) {
    if (s.value.length === 0) continue;
    for (const text of variantsOf(s.value)) {
      if (!variants.has(text)) variants.set(text, { text, name: s.name });
    }
  }
  const all = [...variants.values()];
  const holdBack = Math.max(0, Math.max(0, ...all.map((v) => v.text.length)) - 1);
  let held = "";

  /** Leftmost-longest, non-overlapping matches that start before `limit`. */
  function matchesBefore(
    buf: string,
    limit: number,
  ): { start: number; end: number; name: string }[] {
    const found: { start: number; end: number; name: string }[] = [];
    for (const v of all) {
      for (let i = buf.indexOf(v.text); i !== -1 && i < limit; i = buf.indexOf(v.text, i + 1)) {
        found.push({ start: i, end: i + v.text.length, name: v.name });
      }
    }
    found.sort((a, b) => a.start - b.start || b.end - a.end);
    const kept: typeof found = [];
    let cursor = 0;
    for (const m of found) {
      if (m.start < cursor) continue;
      kept.push(m);
      cursor = m.end;
    }
    return kept;
  }

  function drain(buf: string, limit: number): { out: string; rest: string } {
    let out = "";
    let cursor = 0;
    for (const m of matchesBefore(buf, limit)) {
      out += `${buf.slice(cursor, m.start)}[redacted vault://${m.name}]`;
      cursor = m.end;
    }
    const emitUpTo = Math.max(cursor, limit);
    return { out: out + buf.slice(cursor, emitUpTo), rest: buf.slice(emitUpTo) };
  }

  return {
    push(chunk) {
      const buf = held + chunk;
      let limit = Math.max(0, buf.length - holdBack);
      // Never emit half of a surrogate pair.
      if (limit > 0 && limit < buf.length && isHighSurrogate(buf.charCodeAt(limit - 1))) limit--;
      const { out, rest } = drain(buf, limit);
      held = rest;
      return out;
    },
    flush() {
      const { out } = drain(held, held.length);
      held = "";
      return out;
    },
  };
}
