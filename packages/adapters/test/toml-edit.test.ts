import { describe, expect, test } from "vitest";
import {
  appendTable,
  insertUnderHeader,
  parseToml,
  TomlEditError,
  tomlArray,
  tomlString,
  undoEdit,
} from "../src/toml-edit.js";

const ORIGINAL = [
  "# my codex setup",
  'model = "x"  # keep',
  "",
  "[history]",
  "max_bytes = 5",
  "",
  "# the end",
  "",
].join("\n");

describe("appendTable", () => {
  test("adds a table at the end, keeps every comment, and undoes to the same bytes", () => {
    const { text, edit } = appendTable(ORIGINAL, ["[a.b]", 'k = "v"']);
    expect(text.startsWith(ORIGINAL)).toBe(true);
    expect(parseToml(text)).toMatchObject({ a: { b: { k: "v" } }, model: "x" });
    expect(undoEdit(text, edit)).toBe(ORIGINAL);
  });

  test("a file without a final newline, an empty file and CRLF", () => {
    for (const original of ["a = 1", "", "a = 1\r\nb = 2\r\n", "a = 1\n\n"]) {
      const { text, edit } = appendTable(original, ["[t]", "k = 1"]);
      expect(parseToml(text).t).toEqual({ k: 1 });
      expect(undoEdit(text, edit)).toBe(original);
    }
    expect(appendTable("a = 1\r\n", ["[t]", "k = 1"]).text).toBe("a = 1\r\n\r\n[t]\r\nk = 1\r\n");
  });

  test("two appends undo in either order", () => {
    const one = appendTable(ORIGINAL, ["[one]", "k = 1"]);
    const two = appendTable(one.text, ["[two]", "k = 2"]);
    expect(undoEdit(undoEdit(two.text, two.edit) as string, one.edit)).toBe(ORIGINAL);
    expect(undoEdit(undoEdit(two.text, one.edit) as string, two.edit)).toBe(ORIGINAL);
  });

  test("undo of text that is gone is null", () => {
    const { edit } = appendTable(ORIGINAL, ["[t]", "k = 1"]);
    expect(undoEdit(ORIGINAL, edit)).toBeNull();
  });
});

describe("insertUnderHeader", () => {
  test("puts one line right under the header and undoes to the same bytes", () => {
    const r = insertUnderHeader(ORIGINAL, ["history"], 'persistence = "none"');
    expect(r).not.toBeNull();
    const { text, edit } = r as NonNullable<typeof r>;
    expect(text).toContain('[history]\npersistence = "none"\nmax_bytes = 5');
    expect(parseToml(text).history).toEqual({ persistence: "none", max_bytes: 5 });
    expect(undoEdit(text, edit)).toBe(ORIGINAL);
  });

  test("a header with a trailing comment, quotes and spaces, CRLF, or at the end of the file", () => {
    const cases = [
      "[history] # hist\nk = 1\n",
      '[ "history" ]\nk = 1\n',
      "[history]\r\nk = 1\r\n",
      "[history]",
      "  [history]  \n",
    ];
    for (const original of cases) {
      const r = insertUnderHeader(original, ["history"], "x = 2");
      expect(r, original).not.toBeNull();
      const { text, edit } = r as NonNullable<typeof r>;
      expect(parseToml(text).history, original).toMatchObject({ x: 2 });
      expect(undoEdit(text, edit), original).toBe(original);
    }
    expect(insertUnderHeader("[history]\r\nk = 1\r\n", ["history"], "x = 2")?.text).toBe(
      "[history]\r\nx = 2\r\nk = 1\r\n",
    );
  });

  test("a nested header is matched by its whole path, and an array-of-tables header is not a table", () => {
    const original = '[a]\nx = 1\n[a.b]\ny = 1\n[[c]]\nz = 1\n[projects."/p/[q]"]\nt = 1\n';
    const r = insertUnderHeader(original, ["a", "b"], "n = 3");
    expect(parseToml((r as NonNullable<typeof r>).text).a).toEqual({ x: 1, b: { y: 1, n: 3 } });
    expect(insertUnderHeader(original, ["c"], "n = 3")).toBeNull();
    expect(insertUnderHeader(original, ["b"], "n = 3")).toBeNull();
  });

  test("no such header is null; a header-looking line inside a comment is not one", () => {
    expect(insertUnderHeader("a = 1\n", ["history"], "x = 2")).toBeNull();
    expect(insertUnderHeader("# [history]\na = 1\n", ["history"], "x = 2")).toBeNull();
  });
});

describe("helpers", () => {
  test("strings and arrays are valid TOML, including paths with backslashes and quotes", () => {
    const awkward = 'C:\\Program Files\\a "b"\x7f\n';
    const text = `k = ${tomlString(awkward)}\nl = ${tomlArray(["a", awkward])}\n`;
    expect(parseToml(text)).toEqual({ k: awkward, l: ["a", awkward] });
  });

  test("text that is not TOML is a TomlEditError", () => {
    expect(() => parseToml("a = = 1")).toThrow(TomlEditError);
  });
});
