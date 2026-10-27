import { Readable } from "node:stream";
import { beforeEach, describe, expect, test, vi } from "vitest";
import { fakes } from "../../detect/test/fixtures/fake-keys.js";

type Mod = typeof import("../src/hook-input.js");

// `readHookInput` remembers what it read, so every test gets a fresh module.
let mod: Mod;
beforeEach(async () => {
  vi.resetModules();
  mod = await import("../src/hook-input.js");
});

const stdin = (text: string): Readable => Readable.from([Buffer.from(text)]);
const argv = (event = "prompt-submit") => ["node", "main.js", "hook", "claude-code", event];

describe("fastAllow", () => {
  test("allows a prompt without a key", async () => {
    expect(await mod.fastAllow(argv(), stdin(JSON.stringify({ prompt: "rename it" })))).toBe(true);
  });

  test("defers a prompt with a key, and the full command reads the same input again", async () => {
    const text = JSON.stringify({ prompt: `k ${fakes.githubPat()}` });
    const source = stdin(text);
    expect(await mod.fastAllow(argv(), source)).toBe(false);
    // The stream is spent; the second reader gets the first read back.
    expect(await mod.readHookInput(source)).toEqual({ oversize: false, raw: text });
  });

  test("defers anything it is unsure about", async () => {
    for (const text of ["not json", "", "{", "[]", "null", '{"prompt": 7}', "{}"]) {
      vi.resetModules();
      const fresh = await import("../src/hook-input.js");
      expect(await fresh.fastAllow(argv(), stdin(text)), text).toBe(false);
    }
  });

  test("other events and commands are not touched, and their stdin is not read", async () => {
    const source = stdin("{}");
    const read = vi.spyOn(source, Symbol.asyncIterator);
    expect(await mod.fastAllow(argv("scrub"), source)).toBe(false);
    expect(await mod.fastAllow(["node", "main.js", "status"], source)).toBe(false);
    expect(read).not.toHaveBeenCalled();
  });

  test("a detector that throws defers to the full command (which blocks), never allows", async () => {
    const text = JSON.stringify({ prompt: "rename it" });
    const throwing = () => {
      throw new RangeError("Maximum call stack size exceeded");
    };
    expect(await mod.fastAllow(argv(), stdin(text), throwing)).toBe(false);
  });

  test("a terminal is never read", async () => {
    const source = Object.assign(stdin("x"), { isTTY: true });
    expect(await mod.fastAllow(argv(), source)).toBe(false);
  });
});

describe("readCapped", () => {
  test("reports oversize and drains the rest", async () => {
    const chunks = [Buffer.alloc(6), Buffer.alloc(6), Buffer.alloc(6)];
    const source = Readable.from(chunks);
    expect(await mod.readCapped(source, 10)).toEqual({ oversize: true });
    expect(source.readableEnded).toBe(true);
    expect(await mod.readCapped(Readable.from([Buffer.alloc(10)]), 10)).toMatchObject({
      oversize: false,
    });
  });
});
