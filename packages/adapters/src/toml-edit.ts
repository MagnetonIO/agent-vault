import { parse } from "smol-toml";

/**
 * Text-level edits to a TOML file a person keeps by hand (Codex's `config.toml`). Re-serialising
 * with a TOML library would drop their comments and reorder their tables, so these only splice:
 * append a whole table at the end, or insert one line under an existing table header. Each edit
 * returns the exact text it added, and `undoEdit` removes exactly that, so install followed by
 * uninstall gives the file back byte for byte.
 */

export type TomlEdit =
  /** `text` was added at the very end of the file. */
  | { op: "append"; text: string }
  /** `text` (a line break and one line) was added at the end of the header line of `table`. */
  | { op: "insert"; table: string[]; text: string };

export class TomlEditError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TomlEditError";
  }
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/** The parsed file. Throws `TomlEditError` if the text is not TOML. */
export function parseToml(text: string): Record<string, unknown> {
  try {
    return parse(text);
  } catch (err) {
    throw new TomlEditError(err instanceof Error ? err.message : String(err));
  }
}

/** `s` as a TOML basic string. */
export const tomlString = (s: string): string => JSON.stringify(s).replaceAll("\x7f", "\\u007f");

/** `items` as a one-line TOML array of strings. */
export const tomlArray = (items: string[]): string => `[${items.map(tomlString).join(", ")}]`;

export const eolOf = (text: string): string => (text.includes("\r\n") ? "\r\n" : "\n");

/** `a."b/c"` (the inside of a table header) as `["a", "b/c"]`, or null if it is not a plain header. */
function headerPath(name: string): string[] | null {
  try {
    let node: unknown = parse(`[${name}]`);
    const out: string[] = [];
    while (isRecord(node)) {
      const keys = Object.keys(node);
      if (keys.length !== 1) break;
      out.push(keys[0] as string);
      node = node[keys[0] as string];
    }
    return out;
  } catch {
    return null;
  }
}

/**
 * A `[table]` line (not `[[array]]`), optionally followed by a comment. `\r` is left out of the
 * match. Lines are matched one by one, so a header-looking line inside a multi-line string is
 * taken for a header: a table named by such a line is edited in the wrong place or not found. The
 * parse-and-compare check in `codex.ts` (`checked`) refuses such an edit before any file changes,
 * so the cost is a false refusal, never a wrong edit.
 */
const HEADER_RE = /^[ \t]*\[(?!\[)([^[\]\r\n]+)\][ \t]*(?:#[^\r\n]*)?(?=\r?$)/gm;

/** Any table header, `[[array]]` ones included: the end of a table's own section. */
const ANY_HEADER_RE = /^[ \t]*\[\[?[^[\]\r\n]+\]\]?[ \t]*(?:#[^\r\n]*)?\r?$/gm;

/** Where the header line of `table` ends (before its line break), or -1 if there is none. */
function headerEnd(text: string, table: string[]): number {
  for (const m of text.matchAll(HEADER_RE)) {
    const path = headerPath(m[1] as string);
    if (path && path.length === table.length && path.every((k, i) => k === table[i])) {
      return m.index + m[0].length;
    }
  }
  return -1;
}

/** `lines` as a new block at the end of `text`, set off by a blank line. */
export function appendTable(text: string, lines: string[]): { text: string; edit: TomlEdit } {
  const eol = eolOf(text);
  const sep = text === "" ? "" : text.endsWith("\n") ? eol : eol + eol;
  const added = sep + lines.join(eol) + eol;
  return { text: text + added, edit: { op: "append", text: added } };
}

/** `line` under the header of `table`, or null if the file has no such header. */
export function insertUnderHeader(
  text: string,
  table: string[],
  line: string,
): { text: string; edit: TomlEdit } | null {
  const at = headerEnd(text, table);
  if (at < 0) return null;
  const added = eolOf(text) + line;
  return {
    text: text.slice(0, at) + added + text.slice(at),
    edit: { op: "insert", table, text: added },
  };
}

/** `text` without what `edit` added, or null if that text is no longer there. */
export function undoEdit(text: string, edit: TomlEdit): string | null {
  if (edit.op === "append") {
    if (text.endsWith(edit.text)) return text.slice(0, text.length - edit.text.length);
    const at = text.lastIndexOf(edit.text);
    return at < 0 ? null : text.slice(0, at) + text.slice(at + edit.text.length);
  }
  // Only inside the section of the table it was added to: a line like it in another table is the
  // user's.
  const header = headerEnd(text, edit.table);
  if (header < 0) return null;
  ANY_HEADER_RE.lastIndex = header;
  const sectionEnd = ANY_HEADER_RE.exec(text)?.index ?? text.length;
  const at = text.slice(0, sectionEnd).indexOf(edit.text, header);
  return at < 0 ? null : text.slice(0, at) + text.slice(at + edit.text.length);
}
