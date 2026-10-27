import { parse as parseJsonc } from "jsonc-parser";
import { describe, expect, test } from "vitest";
import { appendAt, JsonEditError, parseJson, removeAt, setAt } from "../src/index.js";

const ENTRY = { hooks: [{ type: "command", command: "x hook y", timeout: 5 }] };

// Each is the file as a person wrote it; install adds to it and uninstall must give it back.
const FILES: Record<string, string> = {
  "two-space": '{\n  "a": 1,\n  "b": { "c": [1, 2] }\n}\n',
  "no trailing newline": '{\n  "a": 1\n}',
  "four-space": '{\n    "a": 1,\n    "b": {"x": 1}\n}\n',
  tabs: '{\n\t"a": 1,\n\t"b": [\n\t\t1\n\t]\n}\n',
  "one line": '{"a":1,"b":[1,2]}',
  comments: '{\n  // keep me\n  "a": 1, // and me\n  /* block */\n  "b": [1,2]\n}\n',
  "empty object": "{}\n",
  "empty object, no newline": "{}",
  crlf: '{\r\n  "a": 1\r\n}\r\n',
  "existing hooks":
    '{\n  "hooks": {\n    "Stop": [\n      { "hooks": [{ "type": "command", "command": "mine" }] }\n    ]\n  }\n}\n',
};

describe("setAt, appendAt, removeAt", () => {
  for (const [name, text] of Object.entries(FILES)) {
    test(`append then remove gives the ${name} file back byte for byte`, () => {
      const added = appendAt(text, ["hooks", "UserPromptSubmit"], ENTRY);
      expect(parseJsonc(added).hooks.UserPromptSubmit).toEqual([ENTRY]);
      // Everything the person wrote is still there, in order.
      const before = parseJsonc(text);
      const after = parseJsonc(added);
      for (const key of Object.keys(before)) {
        if (key !== "hooks") expect(after[key]).toEqual(before[key]);
      }
      expect(removeAt(added, ["hooks", "UserPromptSubmit"])).toBe(text);
    });

    test(`set then remove gives the ${name} file back byte for byte`, () => {
      const added = setAt(text, ["mcpServers", "agent-vault"], { type: "stdio", args: ["mcp"] });
      expect(parseJsonc(added).mcpServers["agent-vault"].args).toEqual(["mcp"]);
      expect(removeAt(added, ["mcpServers", "agent-vault"])).toBe(text);
    });
  }

  test("an insert leaves the rest of the file untouched", () => {
    const text = FILES.comments as string;
    const added = setAt(text, ["apiKeyHelper"], "run it");
    expect(added.startsWith(text.slice(0, text.lastIndexOf("]") + 1))).toBe(true);
    expect(added).toContain("// keep me");
    expect(added).toContain("/* block */");
  });

  test("appending to an array that holds the person's entries removes only ours", () => {
    const text = FILES["existing hooks"] as string;
    const added = appendAt(text, ["hooks", "Stop"], ENTRY);
    expect(parseJsonc(added).hooks.Stop).toHaveLength(2);
    expect(removeAt(added, ["hooks", "Stop", 1])).toBe(text);
  });

  test("removing the last entry of an object takes the empty object with it", () => {
    const added = appendAt("{}\n", ["hooks", "SessionEnd"], ENTRY);
    expect(removeAt(added, ["hooks", "SessionEnd", 0])).toBe("{}\n");
  });

  test("set replaces an existing value in place", () => {
    const text = '{\n  "a": "old",\n  "b": 2\n}\n';
    expect(setAt(text, ["a"], "new")).toBe('{\n  "a": "new",\n  "b": 2\n}\n');
  });

  test("a missing path is a no-op for remove", () => {
    expect(removeAt('{"a":1}', ["b", "c"])).toBe('{"a":1}');
  });

  test("a byte order mark and an empty file are handled", () => {
    expect(setAt("﻿{}\n", ["a"], 1).startsWith("﻿")).toBe(true);
    expect(parseJsonc(setAt("", ["a"], 1))).toEqual({ a: 1 });
  });

  test("text that is not an object is refused", () => {
    expect(() => setAt("[1]", ["a"], 1)).toThrow(JsonEditError);
    expect(() => parseJson('{"a":')).toThrow(JsonEditError);
    expect(() => appendAt('{"a":1}', ["a"], 1)).toThrow(JsonEditError);
  });
});
