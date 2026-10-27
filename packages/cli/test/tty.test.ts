import { PassThrough } from "node:stream";
import { describe, expect, test, vi } from "vitest";
import { readLineFromTty, readSecretFromTty, type TtyInput, type TtyIo } from "../src/tty.js";

class Exit extends Error {
  constructor(readonly code: number) {
    super(`exit ${code}`);
  }
}

/** A terminal that can be typed on: raw-mode changes are recorded, output is collected. */
function fakeTty(isTTY = true) {
  const input = new PassThrough() as PassThrough & TtyInput;
  input.isTTY = isTTY;
  const rawModes: boolean[] = [];
  input.setRawMode = (mode: boolean) => {
    rawModes.push(mode);
    return input;
  };
  let written = "";
  const io: TtyIo = {
    input,
    output: {
      write: (text: string) => {
        written += text;
      },
    },
    exit: (code) => {
      throw new Exit(code);
    },
  };
  return { io, input, rawModes, output: () => written };
}

const type = (input: PassThrough, ...chunks: (string | number[])[]) => {
  for (const chunk of chunks) input.write(Buffer.from(typeof chunk === "string" ? chunk : chunk));
};

describe("readSecretFromTty", () => {
  test("returns what was typed, without echoing it", async () => {
    const t = fakeTty();
    const pending = readSecretFromTty("Value: ", t.io);
    type(t.input, "hunter2-s3cret", "\r");
    const value = await pending;
    expect(Buffer.from(value).toString("utf8")).toBe("hunter2-s3cret");
    expect(t.output()).toBe("Value: \n");
    expect(t.output()).not.toContain("hunter2");
    expect(t.rawModes).toEqual([true, false]);
  });

  test("a value typed in several chunks, ending at Enter, ignores what follows", async () => {
    const t = fakeTty();
    const pending = readSecretFromTty("", t.io);
    type(t.input, "ab", "cd\nignored");
    expect(Buffer.from(await pending).toString()).toBe("abcd");
  });

  test("backspace removes a whole character, including a multi-byte one", async () => {
    const t = fakeTty();
    const pending = readSecretFromTty("", t.io);
    type(t.input, "abé", [0x7f], [0x7f], "c", [0x08], "\r");
    expect(Buffer.from(await pending).toString("utf8")).toBe("a");
  });

  test("backspace on an empty value does nothing", async () => {
    const t = fakeTty();
    const pending = readSecretFromTty("", t.io);
    type(t.input, [0x7f], "x", "\r");
    expect(Buffer.from(await pending).toString()).toBe("x");
  });

  test("arrow keys are not part of the value", async () => {
    const t = fakeTty();
    const pending = readSecretFromTty("", t.io);
    type(t.input, "a", [0x1b, 0x5b, 0x41], "b", [0x1b, 0x5b, 0x31, 0x3b, 0x35, 0x44], "c", "\r");
    expect(Buffer.from(await pending).toString()).toBe("abc");
  });

  test("Ctrl-C exits 130 and puts the terminal back", () => {
    const t = fakeTty();
    void readSecretFromTty("", t.io);
    expect(() => type(t.input, "abc", [0x03])).toThrow(expect.objectContaining({ code: 130 }));
    expect(t.rawModes.at(-1)).toBe(false);
  });

  test("a value longer than the buffer's first size is kept whole", async () => {
    const t = fakeTty();
    const long = "x".repeat(5000);
    const pending = readSecretFromTty("", t.io);
    type(t.input, long, "\r");
    expect(Buffer.from(await pending).toString()).toBe(long);
  });

  test("without a terminal it exits 2 with the instruction", async () => {
    const t = fakeTty(false);
    await expect(readSecretFromTty("Value: ", t.io)).rejects.toMatchObject({ code: 2 });
    expect(t.output()).toBe("Run this in a terminal, or use: agent-vault grab <name>\n");
    expect(t.rawModes).toEqual([]);
  });

  test("defaults to the process's own stdin and stderr", async () => {
    const stderr = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    const exit = vi.spyOn(process, "exit").mockImplementation(((code?: number) => {
      throw new Exit(code ?? 0);
    }) as never);
    const was = process.stdin.isTTY;
    Object.defineProperty(process.stdin, "isTTY", { value: false, configurable: true });
    try {
      await expect(readSecretFromTty("x")).rejects.toMatchObject({ code: 2 });
      expect(stderr).toHaveBeenCalledWith(expect.stringContaining("agent-vault grab <name>"));
    } finally {
      Object.defineProperty(process.stdin, "isTTY", { value: was, configurable: true });
      stderr.mockRestore();
      exit.mockRestore();
    }
  });
});

describe("readLineFromTty", () => {
  test("returns one line, echo left to the terminal", async () => {
    const t = fakeTty();
    const pending = readLineFromTty("Words: ", t.io);
    type(t.input, "one two ", "three\r\nnext");
    expect(await pending).toBe("one two three");
    expect(t.output()).toBe("Words: ");
  });

  test("end of input is an empty line", async () => {
    const t = fakeTty();
    const pending = readLineFromTty("", t.io);
    t.input.end();
    expect(await pending).toBe("");
  });

  test("without a terminal it exits 2", async () => {
    await expect(readLineFromTty("", fakeTty(false).io)).rejects.toMatchObject({ code: 2 });
  });
});
