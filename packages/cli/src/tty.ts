import type { Readable } from "node:stream";
import { CliError } from "./errors.js";

/** The part of a terminal stream the prompts use. `process.stdin` fits. */
export type TtyInput = Readable & {
  isTTY?: boolean;
  setRawMode?: (mode: boolean) => unknown;
};

export type TtyIo = {
  input: TtyInput;
  /** Prompts go here (stderr), so a redirected stdout never holds one. */
  output: { write(text: string): unknown };
  /** Leave the process. Tests replace it with a function that throws. */
  exit?: (code: number) => never;
};

const defaultIo = (): TtyIo => ({ input: process.stdin, output: process.stderr });

const NOT_A_TTY = "Run this in a terminal, or use: agent-vault grab <name>";
const MAX_SECRET_BYTES = 64 * 1024;
const CTRL_C = 0x03;
const CTRL_D = 0x04;
const BACKSPACE = 0x08;
const ENTER = 0x0d;
const NEWLINE = 0x0a;
const ESC = 0x1b;
const DEL = 0x7f;

const leave = (io: TtyIo, code: number): never => (io.exit ?? process.exit)(code);

export const isTty = (input: TtyInput = process.stdin): boolean => input.isTTY === true;

/**
 * Read a value from the terminal with echo off. This is the only way `set` takes a secret: never
 * argv, never env, never a pipe. Without a terminal it exits 2. Ctrl-C exits 130. The bytes are
 * returned in a fresh array and every internal buffer is zeroed; the caller zeroes the result.
 */
export async function readSecretFromTty(
  prompt: string,
  io: TtyIo = defaultIo(),
): Promise<Uint8Array> {
  const { input, output } = io;
  if (!isTty(input) || typeof input.setRawMode !== "function") {
    output.write(`${NOT_A_TTY}\n`);
    return leave(io, 2);
  }
  output.write(prompt);
  input.setRawMode(true);
  input.resume();

  let buf = new Uint8Array(256);
  let len = 0;
  let keySeq: "none" | "esc" | "csi" = "none";

  return new Promise<Uint8Array>((resolve) => {
    const cleanup = () => {
      input.off("data", onData);
      input.setRawMode?.(false);
      input.pause();
      buf.fill(0);
    };
    const finish = () => {
      const out = Uint8Array.from(buf.subarray(0, len));
      cleanup();
      output.write("\n");
      resolve(out);
    };
    const abort = () => {
      cleanup();
      output.write("\n");
      leave(io, 130);
    };
    const push = (byte: number) => {
      if (len >= MAX_SECRET_BYTES) return;
      if (len === buf.length) {
        const grown = new Uint8Array(buf.length * 2);
        grown.set(buf);
        buf.fill(0);
        buf = grown;
      }
      buf[len++] = byte;
    };
    const eraseOneCharacter = () => {
      // UTF-8: drop continuation bytes (10xxxxxx), then the lead byte.
      while (len > 0 && ((buf[len - 1] ?? 0) & 0xc0) === 0x80) buf[--len] = 0;
      if (len > 0) buf[--len] = 0;
    };

    const onData = (chunk: Buffer | string) => {
      const bytes = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
      try {
        for (const byte of bytes) {
          // Arrow keys and the like arrive as ESC [ ... <final byte>; they are not part of a value.
          if (keySeq === "esc") {
            keySeq = byte === 0x5b || byte === 0x4f ? "csi" : "none";
            continue;
          }
          if (keySeq === "csi") {
            if (byte >= 0x40 && byte <= 0x7e) keySeq = "none";
            continue;
          }
          if (byte === ESC) keySeq = "esc";
          else if (byte === CTRL_C) return abort();
          else if (byte === ENTER || byte === NEWLINE || byte === CTRL_D) return finish();
          else if (byte === BACKSPACE || byte === DEL) eraseOneCharacter();
          else if (byte >= 0x20) push(byte);
        }
      } finally {
        bytes.fill(0);
      }
    };
    input.on("data", onData);
  });
}

/**
 * One line from the terminal with echo on (the recovery words). Without a terminal it exits 2;
 * end of input counts as an empty line.
 */
export async function readLineFromTty(prompt: string, io: TtyIo = defaultIo()): Promise<string> {
  const { input, output } = io;
  if (!isTty(input)) {
    output.write("Run this in a terminal.\n");
    return leave(io, 2);
  }
  output.write(prompt);
  input.setEncoding("utf8");
  input.resume();
  return new Promise<string>((resolve) => {
    let text = "";
    const done = (line: string) => {
      input.off("data", onData);
      input.off("end", onEnd);
      input.pause();
      resolve(line);
    };
    const onData = (chunk: string) => {
      text += chunk;
      const nl = text.indexOf("\n");
      if (nl !== -1) done(text.slice(0, nl).replace(/\r$/, ""));
    };
    const onEnd = () => done(text);
    input.on("data", onData);
    input.on("end", onEnd);
  });
}

/** The passphrase for the keyfile store: asked twice when the keyfile does not exist yet. */
export async function promptPassphrase(
  confirm: boolean,
  label = "Keyfile passphrase",
): Promise<string> {
  const decode = (bytes: Uint8Array) => {
    const text = new TextDecoder().decode(bytes);
    bytes.fill(0);
    return text;
  };
  const first = decode(await readSecretFromTty(`${label}: `));
  if (first === "") throw new CliError("the passphrase is empty");
  if (confirm) {
    const again = decode(await readSecretFromTty("Repeat the passphrase: "));
    if (again !== first) throw new CliError("the passphrases differ");
  }
  return first;
}
