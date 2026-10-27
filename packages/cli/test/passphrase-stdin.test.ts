import { PassThrough } from "node:stream";
import { describe, expect, test } from "vitest";
import { readPassphraseLine } from "../src/commands/daemon.js";
import { clipboardValue } from "../src/commands/grab.js";

describe("readPassphraseLine", () => {
  test("reads exactly one line and closes stdin", async () => {
    const input = new PassThrough();
    const pending = readPassphraseLine(input, 1000);
    input.write("first line\r\nsecond line\n");
    expect(await pending).toBe("first line");
    expect(input.destroyed).toBe(true);
  });

  test("a line arriving in pieces", async () => {
    const input = new PassThrough();
    const pending = readPassphraseLine(input, 1000);
    input.write("pass");
    input.write("phrase\n");
    expect(await pending).toBe("passphrase");
  });

  test("end of input without a newline still gives what arrived; none is an error", async () => {
    const some = new PassThrough();
    const pending = readPassphraseLine(some, 1000);
    some.end("no newline");
    expect(await pending).toBe("no newline");

    const none = new PassThrough();
    const empty = readPassphraseLine(none, 1000);
    none.end();
    await expect(empty).rejects.toThrow("no passphrase arrived on stdin");
  });

  test("gives up after the timeout", async () => {
    await expect(readPassphraseLine(new PassThrough(), 50)).rejects.toThrow(
      "timed out waiting for the passphrase on stdin",
    );
  });
});

describe("clipboardValue", () => {
  test("single lines are trimmed of ASCII whitespace", () => {
    expect(clipboardValue("  tok en\t\r\n")).toBe("tok en");
  });

  test("multi-line values are kept exactly", () => {
    expect(clipboardValue("a\nb\n")).toBe("a\nb\n");
    expect(clipboardValue("\n a\nb \n")).toBe("\n a\nb \n");
  });

  test("empty, whitespace-only and non-text are refused", () => {
    expect(() => clipboardValue("")).toThrow("clipboard is empty");
    expect(() => clipboardValue(" \n\t")).toThrow("clipboard is empty");
    expect(() => clipboardValue("a�b")).toThrow("clipboard is not text");
  });
});
