import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import type { RpcError } from "../src/errors.js";
import { scrubFiles } from "../src/scrubber.js";
import { b64, useDaemon } from "./helpers.js";

const SECRET = "sk-test-Zq81xLmN0pRtUvWy3456AbCdEfGh";
const REF = "vault://api/key";
const R = [{ value: SECRET, ref: REF }];

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "avs-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

const write = (name: string, text: string): string => {
  const file = path.join(dir, name);
  fs.writeFileSync(file, text);
  return file;
};
const jsonl = (...objs: unknown[]): string => `${objs.map((o) => JSON.stringify(o)).join("\n")}\n`;
const parseLines = (file: string): unknown[] =>
  fs
    .readFileSync(file, "utf8")
    .split("\n")
    .filter((l) => l !== "")
    .map((l) => JSON.parse(l));
const leftovers = (): string[] => fs.readdirSync(dir).filter((f) => f.includes(".av-scrub-"));

describe("scrubFiles", () => {
  test("replaces the secret on 2 lines and keeps every line valid JSON", async () => {
    const file = write(
      "t.jsonl",
      jsonl(
        { type: "user", text: `my key is ${SECRET}` },
        { type: "note", text: "nothing here" },
        { type: "queue-operation", content: `export K=${SECRET}` },
      ),
    );
    const result = await scrubFiles([file], R);
    expect(result).toMatchObject({ filesChanged: 1, replacements: 2, skipped: [], failed: [] });
    const text = fs.readFileSync(file, "utf8");
    expect(text).not.toContain(SECRET);
    expect(text.split(SECRET)).toHaveLength(1);
    const lines = parseLines(file) as { text?: string; content?: string }[];
    expect(lines).toHaveLength(3);
    expect(lines[0]?.text).toBe(`my key is ${REF}`);
    expect(lines[2]?.content).toBe(`export K=${REF}`);
    expect(leftovers()).toEqual([]);
  });

  test("a PEM key whose newlines are escaped inside JSON is scrubbed", async () => {
    const pem = `-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nKgwggSkAgEAAoIBAQC7\n-----END PRIVATE KEY-----\n`;
    const file = write("pem.jsonl", jsonl({ text: `here:\n${pem}` }, { text: "after" }));
    expect(fs.readFileSync(file, "utf8")).toContain("\\n");
    const result = await scrubFiles([file], [{ value: pem, ref: "vault://pem/key" }]);
    expect(result.replacements).toBe(1);
    expect(fs.readFileSync(file, "utf8")).not.toContain("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC");
    expect((parseLines(file)[0] as { text: string }).text).toBe("here:\nvault://pem/key");
  });

  test("a wrapped base64 copy inside a JSON string is scrubbed", async () => {
    const long = `${SECRET}${SECRET}${SECRET}`;
    const wrapped = Buffer.from(long)
      .toString("base64")
      .replace(/(.{76})/g, "$1\n");
    expect(wrapped).toContain("\n");
    const file = write("w.jsonl", jsonl({ text: `blob:\n${wrapped}` }));
    const result = await scrubFiles([file], [{ value: long, ref: REF }]);
    expect(result.replacements).toBe(1);
    expect(fs.readFileSync(file, "utf8")).not.toContain(wrapped.slice(0, 40));
    expect((parseLines(file)[0] as { text: string }).text).toBe(`blob:\n${REF}`);
  });

  test("a secret split across a 64 KiB chunk boundary is scrubbed", async () => {
    const CHUNK = 64 * 1024;
    for (const offset of [1, 7, SECRET.length - 1]) {
      // The secret starts `offset` bytes before the end of the first chunk.
      const prefix = '{"text":"';
      const text = `${prefix}${"b".repeat(CHUNK - offset - prefix.length)}${SECRET}"}\n`;
      const start = text.indexOf(SECRET);
      expect(start).toBe(CHUNK - offset);
      expect(start + SECRET.length).toBeGreaterThan(CHUNK);
      const file = write(`chunk-${offset}.jsonl`, text);
      const result = await scrubFiles([file], R);
      expect(result.replacements, `offset ${offset}`).toBe(1);
      expect(fs.readFileSync(file, "utf8")).not.toContain(SECRET.slice(0, 12));
      expect(parseLines(file)).toHaveLength(1);
    }
  });

  test("a multi-byte character straddling the chunk boundary survives", async () => {
    const CHUNK = 64 * 1024;
    const text = `${JSON.stringify({ t: `${"é".repeat(CHUNK / 2 + 3)}${SECRET}` })}\n`;
    const file = write("utf8.jsonl", text);
    await scrubFiles([file], R);
    expect(fs.readFileSync(file, "utf8")).toBe(text.replace(SECRET, REF));
  });

  test("a file with no match is untouched: same inode, same mtime, no temp file", async () => {
    const file = write("clean.jsonl", jsonl({ text: "nothing" }));
    const old = new Date("2020-01-02T03:04:05Z");
    fs.utimesSync(file, old, old);
    const before = fs.statSync(file);
    const result = await scrubFiles([file], R);
    expect(result).toEqual({ filesChanged: 0, replacements: 0, skipped: [], failed: [] });
    const after = fs.statSync(file);
    expect(after.ino).toBe(before.ino);
    expect(after.mtimeMs).toBe(before.mtimeMs);
    expect(leftovers()).toEqual([]);
  });

  test("a missing file is skipped without error", async () => {
    const real = write("r.jsonl", jsonl({ text: SECRET }));
    const result = await scrubFiles([path.join(dir, "gone.jsonl"), real], R);
    expect(result).toMatchObject({ filesChanged: 1, replacements: 1, skipped: [], failed: [] });
  });

  test("a symlink is skipped and its target is not rewritten", async () => {
    const target = write("target.jsonl", jsonl({ text: SECRET }));
    const link = path.join(dir, "link.jsonl");
    try {
      fs.symlinkSync(target, link);
    } catch {
      return; // symlinks need a privilege on some Windows setups
    }
    const result = await scrubFiles([link], R);
    expect(result.filesChanged).toBe(0);
    expect(result.skipped).toEqual([{ file: link, reason: "symlink" }]);
    expect(fs.readFileSync(target, "utf8")).toContain(SECRET);
    expect(fs.lstatSync(link).isSymbolicLink()).toBe(true);
  });

  test("a directory is skipped", async () => {
    const sub = path.join(dir, "sub");
    fs.mkdirSync(sub);
    const result = await scrubFiles([sub], R);
    expect(result.skipped).toEqual([{ file: sub, reason: "not a regular file" }]);
  });

  test("a file that is not valid UTF-8 is skipped, never rewritten", async () => {
    const file = path.join(dir, "bin.jsonl");
    const bytes = Buffer.concat([Buffer.from(`${SECRET}\n`), Buffer.from([0xff, 0xfe, 0x80])]);
    fs.writeFileSync(file, bytes);
    const result = await scrubFiles([file], R);
    expect(result.skipped).toEqual([{ file, reason: "not valid UTF-8" }]);
    expect(fs.readFileSync(file).equals(bytes)).toBe(true);
    expect(leftovers()).toEqual([]);
  });

  test("keeps the file mode, the BOM and the modification time", async () => {
    const file = write("m.jsonl", `﻿${jsonl({ text: SECRET })}`);
    fs.chmodSync(file, 0o640);
    const old = new Date("2021-05-06T07:08:09Z");
    fs.utimesSync(file, old, old);
    await scrubFiles([file], R);
    expect(fs.readFileSync(file, "utf8").startsWith("﻿{")).toBe(true);
    if (process.platform !== "win32") expect(fs.statSync(file).mode & 0o777).toBe(0o640);
    expect(fs.statSync(file).mtimeMs).toBe(old.getTime());
  });

  test("two secrets in one pass, each under its own reference", async () => {
    const other = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const file = write("two.jsonl", jsonl({ a: SECRET, b: other }));
    const result = await scrubFiles([file], [...R, { value: other, ref: "vault://gh/pat" }]);
    expect(result.replacements).toBe(2);
    expect(parseLines(file)[0]).toEqual({ a: REF, b: "vault://gh/pat" });
  });

  test("a bare secret name works as a ref", async () => {
    const file = write("bare.jsonl", jsonl({ a: SECRET }));
    await scrubFiles([file], [{ value: SECRET, ref: "api/key" }]);
    expect(parseLines(file)[0]).toEqual({ a: REF });
  });

  test("a result never carries a secret", async () => {
    const file = write("leak.jsonl", jsonl({ a: SECRET }));
    const result = await scrubFiles([file, path.join(dir, "nope")], R);
    expect(JSON.stringify(result)).not.toContain(SECRET);
  });

  describe("concurrent append (Review Focus 3)", () => {
    test("50 lines appended during the scrub are all kept and scrubbed", async () => {
      const filler = JSON.stringify({ type: "assistant", text: "x".repeat(900) });
      const lines: string[] = [];
      for (let i = 0; i < 9000; i++) {
        lines.push(i % 1000 === 0 ? JSON.stringify({ type: "user", text: SECRET }) : filler);
      }
      const file = write("big.jsonl", `${lines.join("\n")}\n`);
      expect(fs.statSync(file).size).toBeGreaterThan(8_000_000);

      let appended = 0;
      let writerDone: () => void = () => {};
      const finished = new Promise<void>((resolve) => {
        writerDone = resolve;
      });
      const timer = setInterval(() => {
        // open-write-close per line, like the harnesses do (docs/spikes/s3-harness-hooks.md)
        fs.appendFileSync(file, `${JSON.stringify({ type: "late", n: appended, text: SECRET })}\n`);
        appended++;
        if (appended === 50) {
          clearInterval(timer);
          writerDone();
        }
      }, 4);
      let result: Awaited<ReturnType<typeof scrubFiles>>;
      let appendedWhenDone: number;
      try {
        result = await scrubFiles([file], R);
        appendedWhenDone = appended;
        await finished;
      } finally {
        clearInterval(timer);
      }

      expect(appendedWhenDone).toBe(50);
      expect(result.filesChanged).toBe(1);
      expect(result.replacements).toBe(9 + 50);
      const text = fs.readFileSync(file, "utf8");
      expect(text).not.toContain(SECRET);
      const parsed = text
        .split("\n")
        .filter((l) => l !== "")
        .map((l) => JSON.parse(l) as { type: string; n?: number; text: string });
      expect(parsed).toHaveLength(9000 + 50);
      const late = parsed.filter((p) => p.type === "late");
      expect(late.map((p) => p.n)).toEqual(Array.from({ length: 50 }, (_, i) => i));
      expect(late.every((p) => p.text === REF)).toBe(true);
      expect(leftovers()).toEqual([]);
    }, 60_000);
  });

  describe("rename failure", () => {
    const busy = (code: string) => Object.assign(new Error(`${code}: busy`), { code });

    test("on Windows the rename is retried and then succeeds", async () => {
      const file = write("retry.jsonl", jsonl({ text: SECRET }));
      let calls = 0;
      const result = await scrubFiles([file], R, {
        platform: "win32",
        rename: async (from, to) => {
          if (++calls <= 2) throw busy("EPERM");
          await fs.promises.rename(from, to);
        },
      });
      expect(calls).toBe(3);
      expect(result).toMatchObject({ filesChanged: 1, replacements: 1, failed: [] });
      expect(fs.readFileSync(file, "utf8")).not.toContain(SECRET);
      expect(leftovers()).toEqual([]);
    });

    test("after 5 failed attempts the file is left as it was, reported, and no temp file stays", async () => {
      const file = write("stuck.jsonl", jsonl({ text: SECRET }));
      const original = fs.readFileSync(file);
      let calls = 0;
      const result = await scrubFiles([file], R, {
        platform: "win32",
        rename: async () => {
          calls++;
          throw busy("EBUSY");
        },
      });
      expect(calls).toBe(5);
      expect(result).toMatchObject({ filesChanged: 0, replacements: 0, skipped: [] });
      expect(result.failed).toEqual([{ file, reason: "EBUSY" }]);
      expect(fs.readFileSync(file).equals(original)).toBe(true);
      expect(leftovers()).toEqual([]);
    });

    test("off Windows a failed rename is not retried", async () => {
      const file = write("posix.jsonl", jsonl({ text: SECRET }));
      let calls = 0;
      const result = await scrubFiles([file], R, {
        platform: "linux",
        rename: async () => {
          calls++;
          throw busy("EPERM");
        },
      });
      expect(calls).toBe(1);
      expect(result.failed).toEqual([{ file, reason: "EPERM" }]);
      expect(leftovers()).toEqual([]);
    });
  });
});

describe("scrub.queue and scrub.run", () => {
  const env = useDaemon("tcp", { init: true });
  let home: string;
  let saved: Record<string, string | undefined>;

  beforeEach(() => {
    // The sandbox rule: nothing here may reach the real home or any real harness file.
    saved = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
    home = fs.mkdtempSync(path.join(os.tmpdir(), "avh-"));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
  });
  afterEach(() => {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    fs.rmSync(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  const put = (name: string, value: string) =>
    env.client.call("secret.put", { name, valueB64: b64(value) });
  const homeFile = (name: string, text: string): string => {
    const file = path.join(home, ".claude", "projects", name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text);
    return file;
  };
  const codeOf = (p: Promise<unknown>): Promise<unknown> =>
    p.then(
      () => "resolved",
      (err: RpcError) => err.code,
    );
  type RunResult = {
    filesChanged: number;
    replacements: number;
    skipped: { file: string; reason: string }[];
    failed: { file: string; reason: string }[];
    dropped: { secret: string; reason: string }[];
    remaining: number;
  };
  const run = () => env.client.call<RunResult>("scrub.run", { harness: "claude-code" });
  const queue = (files: string[], secretNames: string[]) =>
    env.client.call<{ queued: number }>("scrub.queue", {
      harness: "claude-code",
      files,
      secretNames,
    });
  const audit = async (): Promise<{ operation: string; secretName?: string; harness: string }[]> =>
    env.client.call("audit.query", { limit: 100 });

  test("queue then run scrubs the file, clears the rows and audits by name", async () => {
    await put("api/key", SECRET);
    const file = homeFile("s.jsonl", jsonl({ text: SECRET }, { text: `again ${SECRET}` }));
    expect(await queue([file], ["api/key"])).toEqual({ queued: 1 });
    const result = await run();
    expect(result).toEqual({
      filesChanged: 1,
      replacements: 2,
      skipped: [],
      failed: [],
      dropped: [],
      remaining: 0,
    });
    expect(fs.readFileSync(file, "utf8")).not.toContain(SECRET);
    expect((parseLines(file)[1] as { text: string }).text).toBe(`again ${REF}`);

    const events = (await audit()).filter((e) => e.operation === "scrub");
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ secretName: "api/key", harness: "claude-code" });
    const wire = JSON.stringify([result, await audit()]);
    for (const form of [SECRET, b64(SECRET), Buffer.from(SECRET).toString("base64url")]) {
      expect(wire).not.toContain(form);
    }
  });

  test("queueing the same pair twice adds one row", async () => {
    await put("api/key", SECRET);
    const file = homeFile("dup.jsonl", jsonl({ text: SECRET }));
    expect(await queue([file, file], ["api/key", "api/key"])).toEqual({ queued: 1 });
    expect(await queue([file], ["api/key"])).toEqual({ queued: 0 });
  });

  test("a file with several secrets gets one audit event per secret", async () => {
    const other = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    await put("api/key", SECRET);
    await put("gh/pat", other);
    const file = homeFile("two.jsonl", jsonl({ a: SECRET, b: other }));
    await queue([file], ["api/key", "gh/pat"]);
    const result = await run();
    expect(result.replacements).toBe(2);
    const events = (await audit()).filter((e) => e.operation === "scrub");
    expect(events.map((e) => e.secretName).sort()).toEqual(["api/key", "gh/pat"]);
    expect(parseLines(file)[0]).toEqual({ a: REF, b: "vault://gh/pat" });
  });

  test("a file the secret is not in changes nothing and writes no scrub event", async () => {
    await put("api/key", SECRET);
    const file = homeFile("clean.jsonl", jsonl({ text: "nothing" }));
    const before = fs.statSync(file);
    await queue([file], ["api/key"]);
    const result = await run();
    expect(result).toMatchObject({ filesChanged: 0, replacements: 0, remaining: 0 });
    expect(fs.statSync(file).ino).toBe(before.ino);
    expect((await audit()).filter((e) => e.operation === "scrub")).toEqual([]);
  });

  test("a path outside the home directory is refused with -32602", async () => {
    await put("api/key", SECRET);
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "avo-"));
    try {
      const file = path.join(outside, "x.jsonl");
      fs.writeFileSync(file, jsonl({ text: SECRET }));
      expect(await codeOf(queue([file], ["api/key"]))).toBe(-32602);
      expect(await codeOf(queue([path.join(home, "..", "x.jsonl")], ["api/key"]))).toBe(-32602);
      expect(await codeOf(queue(["relative/x.jsonl"], ["api/key"]))).toBe(-32602);
      expect(await codeOf(queue([home], ["api/key"]))).toBe(-32602);
      expect(fs.readFileSync(file, "utf8")).toContain(SECRET);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  test("a directory that is a symlink out of home is refused", async () => {
    await put("api/key", SECRET);
    const outside = fs.mkdtempSync(path.join(os.tmpdir(), "avo-"));
    try {
      try {
        fs.symlinkSync(outside, path.join(home, "escape"), "dir");
      } catch {
        return; // symlinks need a privilege on some Windows setups
      }
      const file = path.join(home, "escape", "x.jsonl");
      expect(await codeOf(queue([file], ["api/key"]))).toBe(-32602);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  });

  test("bad params are refused and an unknown secret is an application error", async () => {
    await put("api/key", SECRET);
    const file = homeFile("p.jsonl", jsonl({ text: SECRET }));
    expect(
      await codeOf(env.client.call("scrub.queue", { files: [file], secretNames: ["api/key"] })),
    ).toBe(-32602);
    expect(await codeOf(env.client.call("scrub.run", { harness: "nope" }))).toBe(-32602);
    expect(await codeOf(env.client.call("scrub.run", {}))).toBe(-32602);
    expect(await codeOf(queue([file], []))).toBe(-32602);
    expect(await codeOf(queue([file], ["Bad Name"]))).toBe(-32602);
    expect(await codeOf(queue([file], ["no/such"]))).toBe(-32000);
  });

  test("rows for a missing file are cleared", async () => {
    await put("api/key", SECRET);
    const file = homeFile("gone.jsonl", jsonl({ text: SECRET }));
    await queue([file], ["api/key"]);
    fs.rmSync(file);
    expect(await run()).toMatchObject({ filesChanged: 0, skipped: [], failed: [], remaining: 0 });
  });

  test("a symlink is skipped, reported and its row cleared", async () => {
    await put("api/key", SECRET);
    const target = homeFile("target.jsonl", jsonl({ text: SECRET }));
    const link = path.join(home, ".claude", "projects", "link.jsonl");
    try {
      fs.symlinkSync(target, link);
    } catch {
      return;
    }
    await queue([link], ["api/key"]);
    const result = await run();
    expect(result.skipped).toEqual([{ file: path.resolve(link), reason: "symlink" }]);
    expect(result.remaining).toBe(0);
    expect(fs.readFileSync(target, "utf8")).toContain(SECRET);
  });

  test("a secret removed since queueing is dropped and noted", async () => {
    await put("api/key", SECRET);
    const file = homeFile("rm.jsonl", jsonl({ text: SECRET }));
    await queue([file], ["api/key"]);
    await env.client.call("secret.remove", { name: "api/key" });
    const result = await run();
    expect(result).toMatchObject({
      filesChanged: 0,
      dropped: [{ secret: "api/key", reason: "removed" }],
      remaining: 0,
    });
    expect(fs.readFileSync(file, "utf8")).toContain(SECRET);
  });

  test("a secret too short to scrub is dropped and noted", async () => {
    await put("pin", "123");
    const file = homeFile("short.jsonl", jsonl({ text: "123" }));
    await queue([file], ["pin"]);
    expect(await run()).toMatchObject({
      dropped: [{ secret: "pin", reason: "too short" }],
      remaining: 0,
    });
  });

  test("a row whose file cannot be rewritten stays queued", async () => {
    if (process.platform === "win32" || process.getuid?.() === 0) return; // needs a read-only dir
    await put("api/key", SECRET);
    const file = homeFile("ro.jsonl", jsonl({ text: SECRET }));
    await queue([file], ["api/key"]);
    const dirPath = path.dirname(file);
    fs.chmodSync(dirPath, 0o555);
    try {
      const result = await run();
      expect(result).toMatchObject({ filesChanged: 0, remaining: 1 });
      expect(result.failed).toEqual([{ file: path.resolve(file), reason: "EACCES" }]);
    } finally {
      fs.chmodSync(dirPath, 0o755);
    }
    expect(await run()).toMatchObject({ filesChanged: 1, replacements: 1, remaining: 0 });
    expect(fs.readFileSync(file, "utf8")).not.toContain(SECRET);
  });

  test("only the named harness's rows run", async () => {
    await put("api/key", SECRET);
    const file = homeFile("h.jsonl", jsonl({ text: SECRET }));
    await queue([file], ["api/key"]);
    expect(await env.client.call("scrub.run", { harness: "codex" })).toMatchObject({
      filesChanged: 0,
      remaining: 0,
    });
    expect(fs.readFileSync(file, "utf8")).toContain(SECRET);
    expect(await run()).toMatchObject({ filesChanged: 1 });
  });
});
