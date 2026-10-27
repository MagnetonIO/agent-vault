import { isValidName } from "./vault.js";

const SCHEME = "vault://";
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

export type EnvEntry = { key: string; ref?: string; literal?: string; line: number };

/** The secret name in `vault://<name>`; null for anything else (no trimming, no query, no slash). */
export function parseRef(s: string): string | null {
  if (typeof s !== "string" || !s.startsWith(SCHEME)) return null;
  const name = s.slice(SCHEME.length);
  return isValidName(name) ? name : null;
}

const ESCAPES: Record<string, string> = { n: "\n", t: "\t", '"': '"', "\\": "\\" };

/**
 * Read a double-quoted value starting after the opening quote. Returns null if the quote never
 * closes, so the caller can fall back to the raw rest of the line.
 */
function readDoubleQuoted(s: string): string | null {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i] as string;
    if (c === '"') return out;
    const esc = c === "\\" ? ESCAPES[s[i + 1] ?? ""] : undefined;
    if (esc === undefined) {
      out += c;
    } else {
      out += esc;
      i++;
    }
  }
  return null;
}

function parseValue(raw: string): string {
  const rest = raw.trimStart();
  const quote = rest[0];
  if (quote === "'" || quote === '"') {
    const body = rest.slice(1);
    // No multi-line values: an unclosed quote keeps the rest of this line as written.
    if (quote === '"') return readDoubleQuoted(body) ?? body;
    const end = body.indexOf("'");
    return end === -1 ? body : body.slice(0, end);
  }
  // A comment starts at a # with whitespace before it, so `a#b` stays intact.
  const comment = /\s#/.exec(raw);
  return (comment ? raw.slice(0, comment.index) : raw).trim();
}

/**
 * Parse `.env` text into keys with either a `vault://` ref (the secret name) or a literal. Lines
 * that are not `KEY=value` with a valid key are skipped; line numbers are 1-based and count them.
 * Never throws.
 */
export function parseEnvFile(text: string): EnvEntry[] {
  const out: EnvEntry[] = [];
  const lines = String(text).replace(/^﻿/, "").split(/\r?\n/);
  lines.forEach((full, i) => {
    const line = full.trimStart();
    if (line === "" || line.startsWith("#")) return;
    const body = line.replace(/^export\s+/, "");
    const eq = body.indexOf("=");
    if (eq === -1) return;
    const key = body.slice(0, eq).trim();
    if (!ENV_KEY_RE.test(key)) return;
    const value = parseValue(body.slice(eq + 1));
    const ref = parseRef(value);
    out.push(ref === null ? { key, literal: value, line: i + 1 } : { key, ref, line: i + 1 });
  });
  return out;
}
