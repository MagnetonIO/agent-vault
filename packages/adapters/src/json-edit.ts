import { type Node, type ParseError, parse as parseJsonc, parseTree } from "jsonc-parser";

/**
 * Minimal edits to a JSON file that may hold comments and trailing commas (a harness's settings).
 * `jsonc-parser`'s `modify` re-indents the whole document on an insert, so a user's file would
 * change everywhere. These splice text instead: an insert adds one entry and a remove deletes
 * exactly what an insert added, so install followed by uninstall gives the file back byte for byte.
 */

export type JsonPath = (string | number)[];

export class JsonEditError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "JsonEditError";
  }
}

type Style = { eol: string; unit: string };

const BOM = "﻿";

/** Line ending and one level of indentation, as the file already uses them. */
function styleOf(text: string): Style {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const indented = /^([ \t]+)[^\s/]/m.exec(text);
  const lead = indented?.[1] ?? "  ";
  const unit = lead.startsWith("\t") ? "\t" : lead.length > 8 ? "  " : lead;
  return { eol, unit };
}

/** Whitespace at the start of the line that holds `offset`. */
function lineIndent(text: string, offset: number): string {
  const start = text.lastIndexOf("\n", offset - 1) + 1;
  return /^[ \t]*/.exec(text.slice(start))?.[0] ?? "";
}

/** True if nothing but whitespace sits between the start of the line and `offset`. */
function startsLine(text: string, offset: number): boolean {
  const start = text.lastIndexOf("\n", offset - 1) + 1;
  return /^[ \t]*$/.test(text.slice(start, offset));
}

function tree(text: string): Node {
  const errors: ParseError[] = [];
  const root = parseTree(text, errors, { allowTrailingComma: true });
  if (errors.length > 0 || !root) throw new JsonEditError("not valid JSON");
  if (root.type !== "object") throw new JsonEditError("the top level is not an object");
  return root;
}

/** The parsed value (comments and trailing commas allowed), or throws if the text is not JSON. */
export function parseJson(text: string): Record<string, unknown> {
  const clean = text.startsWith(BOM) ? text.slice(1) : text;
  if (clean.trim() === "") return {};
  tree(clean); // validates, and requires an object at the top
  return parseJsonc(clean, [], { allowTrailingComma: true }) as Record<string, unknown>;
}

/** Wraps `fn` so an empty file counts as `{}` and a byte order mark survives. */
function edit(text: string, fn: (text: string) => string): string {
  const bom = text.startsWith(BOM) ? BOM : "";
  const body = text.slice(bom.length);
  return bom + fn(body.trim() === "" ? "{}\n" : body);
}

/** The LAST property named `key`: the one `JSON.parse` keeps when a key is repeated. */
function propertyOf(obj: Node, key: string): Node | undefined {
  return obj.children?.findLast((p) => p.children?.[0]?.value === key);
}

type Step = { node: Node; prop?: Node };

/** Walk `path`; the last step's `node` is the value there, or undefined where it is missing. */
function walk(root: Node, path: JsonPath): { found: Step[]; missingAt: number } {
  const found: Step[] = [{ node: root }];
  let node = root;
  for (let i = 0; i < path.length; i++) {
    const key = path[i] as string | number;
    let next: Node | undefined;
    let prop: Node | undefined;
    if (node.type === "object" && typeof key === "string") {
      prop = propertyOf(node, key);
      next = prop?.children?.[1];
    } else if (node.type === "array" && typeof key === "number") {
      next = node.children?.[key];
    } else {
      throw new JsonEditError(`cannot step into ${String(key)}: not a container of that kind`);
    }
    if (!next) return { found, missingAt: i };
    found.push({ node: next, ...(prop && { prop }) });
    node = next;
  }
  return { found, missingAt: -1 };
}

const nest = (path: JsonPath, value: unknown): unknown =>
  path.reduceRight<unknown>((inner, key) => {
    if (typeof key !== "string") throw new JsonEditError("cannot create an array item by index");
    return { [key]: inner };
  }, value);

/** `value` as text for a container at `indent`: multi-line like the file, or one line. */
function render(value: unknown, indent: string, multi: boolean, style: Style): string {
  if (!multi) return JSON.stringify(value);
  return JSON.stringify(value, null, style.unit)
    .split("\n")
    .join(style.eol + indent);
}

/** Add one entry (`key` for an object) at the end of `container`. */
function insertChild(text: string, container: Node, key: string | undefined, value: unknown) {
  const style = styleOf(text);
  const kids = container.children ?? [];
  const open = container.offset;
  const close = container.offset + container.length - 1;
  const entry = (indent: string, multi: boolean): string =>
    (key === undefined ? "" : `${JSON.stringify(key)}${multi ? ": " : ":"}`) +
    render(value, indent, multi, style);

  const last = kids[kids.length - 1];
  if (!last) {
    const base = lineIndent(text, open);
    const inner = base + style.unit;
    const head = `${text.slice(0, open + 1)}${style.eol}${inner}${entry(inner, true)}`;
    // Whatever sits inside the empty container (a comment, a line break) stays after the entry.
    if (close > open + 1) return head + text.slice(open + 1);
    return `${head}${style.eol}${base}${text.slice(close)}`;
  }
  const lastEnd = last.offset + last.length;
  if (startsLine(text, last.offset)) {
    const indent = lineIndent(text, last.offset);
    return `${text.slice(0, lastEnd)},${style.eol}${indent}${entry(indent, true)}${text.slice(lastEnd)}`;
  }
  return `${text.slice(0, lastEnd)},${entry("", false)}${text.slice(lastEnd)}`;
}

const isWs = (ch: string | undefined): boolean =>
  ch === " " || ch === "\t" || ch === "\n" || ch === "\r";

/**
 * Delete `child` from `container`, with the comma and the line break that went with it. Comments
 * are never deleted: a comment between two entries stays with the entry that follows it.
 */
function deleteChild(text: string, container: Node, child: Node): string {
  const kids = container.children ?? [];
  const i = kids.indexOf(child);
  const close = container.offset + container.length - 1;
  const childEnd = child.offset + child.length;
  if (kids.length === 1) {
    let start = child.offset;
    while (start > container.offset + 1 && isWs(text[start - 1])) start--;
    let after = childEnd;
    while (after < close && isWs(text[after])) after++;
    // The white space before the closing bracket goes too, unless a comment follows the entry.
    return text.slice(0, start) + text.slice(after === close ? after : childEnd);
  }
  if (i < kids.length - 1) {
    // From the entry through its comma and the white space after it; a comment there stays.
    let pos = childEnd;
    while (isWs(text[pos])) pos++;
    const end = text[pos] === "," ? pos + 1 : -1;
    if (end === -1) return text.slice(0, child.offset) + text.slice((kids[i + 1] as Node).offset);
    let next = end;
    while (isWs(text[next])) next++;
    return text.slice(0, child.offset) + text.slice(next);
  }
  const prev = kids[i - 1] as Node;
  const prevEnd = prev.offset + prev.length;
  let comma = prevEnd;
  while (isWs(text[comma])) comma++;
  if (text[comma] !== ",") return text.slice(0, prevEnd) + text.slice(childEnd);
  const between = text.slice(comma + 1, child.offset);
  if (between.trim() === "") return text.slice(0, prevEnd) + text.slice(childEnd);
  // A comment sits between the comma and the entry: keep it, drop the comma and the entry.
  let wsStart = child.offset;
  while (wsStart > comma + 1 && isWs(text[wsStart - 1])) wsStart--;
  return text.slice(0, prevEnd) + text.slice(comma + 1, wsStart) + text.slice(childEnd);
}

/** Set the value at `path`: replaced if it exists, added (with any objects above it) if not. */
export function setAt(text: string, path: JsonPath, value: unknown): string {
  return edit(text, (body) => {
    const { found, missingAt } = walk(tree(body), path);
    if (missingAt === -1) {
      const at = found[found.length - 1] as Step;
      const indent = lineIndent(body, (at.prop ?? at.node).offset);
      const multi = typeof value === "object" && value !== null;
      return (
        body.slice(0, at.node.offset) +
        render(value, indent, multi, styleOf(body)) +
        body.slice(at.node.offset + at.node.length)
      );
    }
    const parent = (found[found.length - 1] as Step).node;
    const key = path[missingAt] as string | number;
    if (parent.type !== "object" || typeof key !== "string") {
      throw new JsonEditError("cannot add an entry here");
    }
    return insertChild(body, parent, key, nest(path.slice(missingAt + 1), value));
  });
}

/** Append `value` to the array at `path`; the array (and objects above it) is created if absent. */
export function appendAt(text: string, path: JsonPath, value: unknown): string {
  return edit(text, (body) => {
    const { found, missingAt } = walk(tree(body), path);
    if (missingAt === -1) {
      const arr = (found[found.length - 1] as Step).node;
      if (arr.type !== "array") throw new JsonEditError(`${path.join(".")} is not an array`);
      return insertChild(body, arr, undefined, value);
    }
    const parent = (found[found.length - 1] as Step).node;
    const key = path[missingAt] as string | number;
    if (parent.type !== "object" || typeof key !== "string") {
      throw new JsonEditError("cannot add an entry here");
    }
    return insertChild(body, parent, key, nest(path.slice(missingAt + 1), [value]));
  });
}

/** Says whether the container at this path was created by an insert, so a remove may take it. */
export type PruneFn = (containerPath: JsonPath) => boolean;

/**
 * Remove what is at `path`. A container that this leaves empty goes too if `prune` says an insert
 * created it, up to (not including) the top-level object. Without `prune` only the entry goes. A
 * missing path is a no-op.
 */
export function removeAt(text: string, path: JsonPath, prune?: PruneFn): string {
  return edit(text, (body) => {
    const { found, missingAt } = walk(tree(body), path);
    if (missingAt !== -1) return body;
    let level = found.length - 1;
    while (
      prune &&
      level > 1 &&
      (found[level - 1] as Step).node.children?.length === 1 &&
      prune(path.slice(0, level - 1))
    ) {
      level--;
    }
    const child = found[level] as Step;
    const container = (found[level - 1] as Step).node;
    return deleteChild(body, container, child.prop ?? child.node);
  });
}

/**
 * The containers along `path` (prefixes of it, root excluded) that `text` does not have yet: what
 * an insert at `path` would create. Pass the path of the array or object that receives the entry.
 */
export function missingContainers(text: string, path: JsonPath): JsonPath[] {
  const { missingAt } = walk(tree(text.trim() === "" ? "{}" : text.replace(/^\uFEFF/, "")), path);
  if (missingAt === -1) return [];
  return path.slice(missingAt).map((_, k) => path.slice(0, missingAt + k + 1));
}
