import { parse as parseJsonc } from "jsonc-parser";
import { describe, expect, test } from "vitest";
import {
  addHooksTracked,
  appendAt,
  JsonEditError,
  type JsonPath,
  missingContainers,
  parseJson,
  removeAt,
  removeHooks,
  setAt,
} from "../src/index.js";

const pruneOf = (created: JsonPath[]) => (c: JsonPath) =>
  created.some((p) => p.join("\0") === c.join("\0"));

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
      const created = missingContainers(text, ["hooks", "UserPromptSubmit"]);
      expect(removeAt(added, ["hooks", "UserPromptSubmit"], pruneOf(created))).toBe(text);
    });

    test(`set then remove gives the ${name} file back byte for byte`, () => {
      const added = setAt(text, ["mcpServers", "agent-vault"], { type: "stdio", args: ["mcp"] });
      expect(parseJsonc(added).mcpServers["agent-vault"].args).toEqual(["mcp"]);
      const created = missingContainers(text, ["mcpServers"]);
      expect(removeAt(added, ["mcpServers", "agent-vault"], pruneOf(created))).toBe(text);
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
    const created = missingContainers("{}\n", ["hooks", "SessionEnd"]);
    expect(created).toEqual([["hooks"], ["hooks", "SessionEnd"]]);
    expect(removeAt(added, ["hooks", "SessionEnd", 0], pruneOf(created))).toBe("{}\n");
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

describe("remove takes only what an insert created", () => {
  test("containers the person already had stay, empty or not", () => {
    for (const text of [
      '{"hooks":{}}',
      '{\n  "hooks": {}\n}\n',
      '{"hooks":{"UserPromptSubmit":[]}}',
      '{\n  "hooks": {\n    "UserPromptSubmit": []\n  }\n}\n',
    ]) {
      const created = missingContainers(text, ["hooks", "UserPromptSubmit"]);
      const added = appendAt(text, ["hooks", "UserPromptSubmit"], ENTRY);
      expect(removeAt(added, ["hooks", "UserPromptSubmit", 0], pruneOf(created)), text).toBe(text);
    }
    // Without a record of what was created, nothing but the entry goes.
    const added = appendAt("{}\n", ["hooks", "Stop"], ENTRY);
    expect(removeAt(added, ["hooks", "Stop", 0])).toBe('{\n  "hooks": {\n    "Stop": []\n  }\n}\n');
  });

  test("a comment inside an empty container survives the insert and the remove", () => {
    for (const text of [
      '{ "hooks": { /* keep */ } }',
      '{\n  "hooks": {\n    // keep me\n  }\n}\n',
      '{\n  "hooks": {\n    "Stop": [\n      // keep me too\n    ]\n  }\n}\n',
    ]) {
      const created = missingContainers(text, ["hooks", "Stop"]);
      const added = appendAt(text, ["hooks", "Stop"], ENTRY);
      expect(added).toContain("keep");
      expect(parseJsonc(added).hooks.Stop).toBeDefined();
      expect(removeAt(added, ["hooks", "Stop", 0], pruneOf(created)), text).toBe(text);
    }
  });

  test("a comment before a group that follows ours stays when ours goes", () => {
    const text = [
      "{",
      '  "hooks": {',
      '    "UserPromptSubmit": [',
      '      { "hooks": [{ "type": "command", "command": "OURS" }] },',
      "      // about the user's group",
      '      { "hooks": [{ "type": "command", "command": "mine" }] }',
      "    ]",
      "  }",
      "}",
      "",
    ].join("\n");
    expect(
      removeHooks(
        text,
        (c) => c === "OURS",
        () => true,
      ),
    ).toBe(text.replace('      { "hooks": [{ "type": "command", "command": "OURS" }] },\n', ""));
    // And when ours is the last and a comment sits between the user's group and it.
    const last = [
      "{",
      '  "hooks": {',
      '    "UserPromptSubmit": [',
      '      { "hooks": [{ "type": "command", "command": "mine" }] }, // theirs',
      "      // before ours",
      '      { "hooks": [{ "type": "command", "command": "OURS" }] }',
      "    ]",
      "  }",
      "}",
      "",
    ].join("\n");
    const after = removeHooks(
      last,
      (c) => c === "OURS",
      () => true,
    );
    expect(after).toContain("// theirs");
    expect(after).toContain("// before ours");
    expect(parseJsonc(after).hooks.UserPromptSubmit).toHaveLength(1);
  });

  test("with a repeated key, the last one is the one that is read, set and removed", () => {
    const text = '{\n  "apiKeyHelper": "first",\n  "apiKeyHelper": "second"\n}\n';
    expect(parseJsonc(setAt(text, ["apiKeyHelper"], "new")).apiKeyHelper).toBe("new");
    expect(setAt(text, ["apiKeyHelper"], "new")).toBe(
      '{\n  "apiKeyHelper": "first",\n  "apiKeyHelper": "new"\n}\n',
    );
    expect(removeAt(text, ["apiKeyHelper"])).toBe('{\n  "apiKeyHelper": "first"\n}\n');
  });
});

// A small seeded generator, so a failure names its seed.
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe("install then uninstall over generated files", () => {
  const specs = [
    { event: "UserPromptSubmit", command: "/bin/x hook claude-code prompt-submit", timeout: 30 },
    { event: "SessionEnd", command: "/bin/x hook claude-code scrub", timeout: 15 },
    { event: "SessionStart", command: "/bin/x hook claude-code scrub", timeout: 15 },
  ];
  const HOOKS = [
    null,
    '"hooks": {}',
    '"hooks": { /* keep */ }',
    '"hooks": {\n__I__// keep me\n}',
    '"hooks": {"UserPromptSubmit": []}',
    '"hooks": {"SessionEnd": [ /* keep */ ]}',
    '"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "mine"}]}]}',
    '"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command", "command": "mine"}]}],\n__I__"SessionStart": []}',
  ];
  const OTHERS = ['"model": "opus"', '"env": {"A": "1"}', '"list": [1, 2]'];

  test("every file comes back byte for byte", () => {
    let n = 0;
    for (let seed = 1; seed <= 400; seed++) {
      const r = rng(seed);
      const pick = <T>(xs: T[]): T => xs[Math.floor(r() * xs.length)] as T;
      const indent = pick(["  ", "    ", "\t", ""]);
      const eol = pick(["\n", "\r\n"]);
      const entries = OTHERS.filter(() => r() < 0.5);
      const hooks = pick(HOOKS);
      if (hooks)
        entries.splice(
          Math.floor(r() * (entries.length + 1)),
          0,
          hooks.replaceAll("__I__", indent.repeat(2)),
        );
      if (r() < 0.3) entries.unshift("// my settings");
      const sep = indent === "" ? " " : `${eol}${indent}`;
      let body = entries
        .map(
          (e, i) =>
            (e.startsWith("//") ? e : e) +
            (i < entries.length - 1 && !e.startsWith("//") ? "," : ""),
        )
        .join(sep);
      body = body.replaceAll("\n", eol);
      const text =
        entries.length === 0
          ? pick(["{}", "{}\n"])
          : indent === ""
            ? `{ ${body} }`
            : `{${eol}${indent}${body}${eol}}${pick(["", eol])}`;
      let valid = true;
      try {
        parseJson(text);
      } catch {
        valid = false;
      }
      if (!valid) continue; // the generator is allowed to make a comment swallow a comma
      const { text: added, created } = addHooksTracked(text, specs, "hook claude-code");
      expect(parseJson(added), `seed ${seed}`).toBeTypeOf("object");
      const back = removeHooks(added, "hook claude-code", pruneOf(created));
      expect(back, `seed ${seed}: ${JSON.stringify(text)}`).toBe(text);
      n++;
    }
    expect(n).toBeGreaterThan(150);
  });
});
