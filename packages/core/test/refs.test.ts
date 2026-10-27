import { describe, expect, test } from "vitest";
import { isValidEnvName, isValidName } from "../src/index.js";
import { parseEnvFile, parseRef } from "../src/refs.js";

describe("parseRef", () => {
  test.each([
    ["vault://github/token", "github/token"],
    ["vault://a", "a"],
    ["vault://stripe.live-key_1", "stripe.live-key_1"],
  ])("%s -> %s", (input, name) => {
    expect(parseRef(input)).toBe(name);
  });

  test.each([
    ["empty", ""],
    ["no name", "vault://"],
    ["no scheme", "github/token"],
    ["wrong scheme", "vaults://a"],
    ["uppercase scheme", "VAULT://a"],
    ["leading space", " vault://a"],
    ["trailing space", "vault://a "],
    ["trailing newline", "vault://a\n"],
    ["inner whitespace", "vault://a b"],
    ["trailing slash", "vault://a/"],
    ["leading slash", "vault:///a"],
    ["query string", "vault://a?x=1"],
    ["fragment", "vault://a#frag"],
    ["uppercase name", "vault://Github"],
    ["double slash in name", "vault://a//b"],
    ["dot-dot", "vault://../etc"],
    ["leading dash", "vault://-a"],
    ["name too long", `vault://${"a".repeat(129)}`],
    ["embedded in text", "x vault://a"],
  ])("rejects %s", (_label, input) => {
    expect(parseRef(input)).toBeNull();
  });

  test("accepts a 128-char name", () => {
    expect(parseRef(`vault://${"a".repeat(128)}`)).toBe("a".repeat(128));
  });

  test("non-string input returns null instead of throwing", () => {
    expect(parseRef(undefined as unknown as string)).toBeNull();
    expect(parseRef(42 as unknown as string)).toBeNull();
  });
});

describe("parseEnvFile", () => {
  test("literals and refs, with 1-based line numbers", () => {
    const text = ["# header", "", "A=plain", "B=vault://github/token", "C="].join("\n");
    expect(parseEnvFile(text)).toEqual([
      { key: "A", literal: "plain", line: 3 },
      { key: "B", ref: "github/token", line: 4 },
      { key: "C", literal: "", line: 5 },
    ]);
  });

  test("CRLF line endings", () => {
    expect(parseEnvFile("A=1\r\nB=vault://x\r\n\r\nC=3\r\n")).toEqual([
      { key: "A", literal: "1", line: 1 },
      { key: "B", ref: "x", line: 2 },
      { key: "C", literal: "3", line: 4 },
    ]);
  });

  test("lone CR line endings", () => {
    expect(parseEnvFile("A=vault://x\rB=vault://y\rC=3")).toEqual([
      { key: "A", ref: "x", line: 1 },
      { key: "B", ref: "y", line: 2 },
      { key: "C", literal: "3", line: 3 },
    ]);
  });

  test("export prefix", () => {
    expect(parseEnvFile("export A=1\nexport   B=vault://b\n  export C=3")).toEqual([
      { key: "A", literal: "1", line: 1 },
      { key: "B", ref: "b", line: 2 },
      { key: "C", literal: "3", line: 3 },
    ]);
  });

  test("a key named export is not a prefix", () => {
    expect(parseEnvFile("export=1")).toEqual([{ key: "export", literal: "1", line: 1 }]);
  });

  test("full-line comments and blank lines are skipped, line numbers stay right", () => {
    const out = parseEnvFile("# one\n   # indented\n\n   \nA=1");
    expect(out).toEqual([{ key: "A", literal: "1", line: 5 }]);
  });

  test("single quotes are literal", () => {
    expect(parseEnvFile(`A='a\\nb "c" $X'`)).toEqual([
      { key: "A", literal: 'a\\nb "c" $X', line: 1 },
    ]);
  });

  test('double quotes support \\n \\t \\" \\\\ escapes', () => {
    expect(parseEnvFile('A="a\\nb\\tc\\"d\\\\e"')).toEqual([
      { key: "A", literal: 'a\nb\tc"d\\e', line: 1 },
    ]);
  });

  test("unknown escapes in double quotes are kept as written", () => {
    expect(parseEnvFile('A="a\\qb"')).toEqual([{ key: "A", literal: "a\\qb", line: 1 }]);
  });

  test("quoted ref is still a ref", () => {
    expect(parseEnvFile(`A="vault://x"\nB='vault://y'`)).toEqual([
      { key: "A", ref: "x", line: 1 },
      { key: "B", ref: "y", line: 2 },
    ]);
  });

  test("quoted whitespace is preserved; unquoted is trimmed", () => {
    expect(parseEnvFile(`A="  pad  "\nB=   trimmed   \nC=' x '`)).toEqual([
      { key: "A", literal: "  pad  ", line: 1 },
      { key: "B", literal: "trimmed", line: 2 },
      { key: "C", literal: " x ", line: 3 },
    ]);
  });

  test("inline # needs whitespace before it", () => {
    expect(parseEnvFile("A=value # note\nB=a#b\nC=vault://x   # why\nD= # only comment")).toEqual([
      { key: "A", literal: "value", line: 1 },
      { key: "B", literal: "a#b", line: 2 },
      { key: "C", ref: "x", line: 3 },
      { key: "D", literal: "", line: 4 },
    ]);
  });

  test("# inside quotes is data; a comment after the closing quote is ignored", () => {
    expect(parseEnvFile(`A="x # y" # c\nB='p #q' # c\nC="#hash"`)).toEqual([
      { key: "A", literal: "x # y", line: 1 },
      { key: "B", literal: "p #q", line: 2 },
      { key: "C", literal: "#hash", line: 3 },
    ]);
  });

  test("empty values: bare, double-quoted and single-quoted", () => {
    expect(parseEnvFile(`A=\nB=""\nC=''`)).toEqual([
      { key: "A", literal: "", line: 1 },
      { key: "B", literal: "", line: 2 },
      { key: "C", literal: "", line: 3 },
    ]);
  });

  test("invalid key lines are skipped silently, numbering stays correct", () => {
    const text = [
      "1BAD=x",
      "has space=x",
      "=novalue",
      "no equals sign",
      "-x=1",
      "OK=1",
      "a.b=2",
    ].join("\n");
    expect(parseEnvFile(text)).toEqual([{ key: "OK", literal: "1", line: 6 }]);
  });

  test("whitespace around = and before the key is tolerated", () => {
    expect(parseEnvFile("  A = 1")).toEqual([{ key: "A", literal: "1", line: 1 }]);
  });

  test("an unclosed quote takes the rest of the line literally", () => {
    expect(parseEnvFile(`A="abc\\n def\nB='xyz\nC=1`)).toEqual([
      { key: "A", literal: "abc\\n def", line: 1 },
      { key: "B", literal: "xyz", line: 2 },
      { key: "C", literal: "1", line: 3 },
    ]);
  });

  test("only the first = splits key from value", () => {
    expect(parseEnvFile("A=b=c")).toEqual([{ key: "A", literal: "b=c", line: 1 }]);
  });

  test("invalid ref stays a literal", () => {
    expect(parseEnvFile("A=vault://Bad Name\nB=vault://")).toEqual([
      { key: "A", literal: "vault://Bad Name", line: 1 },
      { key: "B", literal: "vault://", line: 2 },
    ]);
  });

  test("a UTF-8 BOM on the first line is ignored", () => {
    expect(parseEnvFile("﻿A=1")).toEqual([{ key: "A", literal: "1", line: 1 }]);
  });

  test("never throws on junk", () => {
    expect(() => parseEnvFile("\0\0=\n\"\n'\n=\n\\")).not.toThrow();
    expect(parseEnvFile("")).toEqual([]);
  });
});

describe("isValidName / isValidEnvName (the one copy every package uses)", () => {
  test("secret names", () => {
    for (const ok of ["a", "github/pat-20261027", "mcp/x.y_z"])
      expect(isValidName(ok), ok).toBe(true);
    for (const bad of ["", "A", "/a", "a/", "a//b", "-a", "a".repeat(129), 7]) {
      expect(isValidName(bad), String(bad)).toBe(false);
    }
  });

  test("env names", () => {
    for (const ok of ["A", "_x", "API_KEY2"]) expect(isValidEnvName(ok), ok).toBe(true);
    for (const bad of ["", "2A", "A-B", "A B", null]) {
      expect(isValidEnvName(bad), String(bad)).toBe(false);
    }
  });
});
