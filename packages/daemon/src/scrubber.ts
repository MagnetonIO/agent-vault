import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { createBlockScrubber, JsonCorruptionError, REF_PREFIX } from "./scrub-text.js";

/** How much of a file is read, redacted and written at a time. */
const CHUNK_BYTES = 64 * 1024;
/** The gap between the size checks that decide the file has stopped growing. */
const STABLE_CHECK_MS = 50;
const MAX_STABLE_LOOPS = 20;
/** How many times the final size check may find more bytes and send the scrub back to reading. */
const MAX_FINAL_ROUNDS = 5;
/** A line longer than this (in characters) is not held in memory: the file fails. */
const MAX_LINE_CHARS = 64 * 1024 * 1024;
/** A leftover `.av-scrub-*` temp file is deleted when its process is gone or it is this old. */
const STALE_TEMP_MS = 10 * 60_000;
/** Creating the temp file failed because the directory refuses it: retrying will not help. */
const UNWRITABLE_CODES: ReadonlySet<string> = new Set(["EACCES", "EPERM", "EROFS"]);
/** Windows refuses to replace a file another process has open; try again for a moment. */
const RENAME_ATTEMPTS = 5;
const RENAME_BACKOFF_MS = 100;
const RENAME_RETRY_CODES: ReadonlySet<string> = new Set(["EPERM", "EBUSY", "EACCES"]);

export type Replacement = {
  /** The secret as the user typed it. */
  value: string;
  /** `vault://name`, or the bare name. */
  ref: string;
};

export type FileProblem = { file: string; reason: string };

export type ScrubResult = {
  filesChanged: number;
  /** Redactions made in the files that were rewritten. */
  replacements: number;
  /** Files that were deliberately not touched (symlink, hard link, not a regular file, not UTF-8, directory not writable). */
  skipped: FileProblem[];
  /** Files that should be tried again later (rename refused, kept growing, line too large, I/O error). */
  failed: FileProblem[];
};

export type ScrubOptions = {
  /** Replaces `fs.promises.rename`; tests make it fail. */
  rename?: (from: string, to: string) => Promise<void>;
  /** Replaces `process.platform`; only `win32` retries a refused rename. */
  platform?: NodeJS.Platform;
  /** Runs after the data is synced and before the last size check; tests append to the file here. */
  beforeFinalCheck?: () => void | Promise<void>;
};

type Outcome =
  | { kind: "missing" }
  | { kind: "clean" }
  | { kind: "changed"; replacements: number }
  | { kind: "skipped"; reason: string }
  | { kind: "failed"; reason: string };

const errCode = (err: unknown): string =>
  typeof (err as { code?: unknown })?.code === "string" ? (err as { code: string }).code : "error";

const isGone = (err: unknown): boolean => ["ENOENT", "ENOTDIR"].includes(errCode(err));

async function renameWithRetry(
  rename: (from: string, to: string) => Promise<void>,
  from: string,
  to: string,
  retry: boolean,
): Promise<void> {
  for (let attempt = 1; ; attempt++) {
    try {
      await rename(from, to);
      return;
    } catch (err) {
      if (!retry || !RENAME_RETRY_CODES.has(errCode(err)) || attempt >= RENAME_ATTEMPTS) throw err;
      await sleep(RENAME_BACKOFF_MS);
    }
  }
}

/** Thrown inside `scrubOne` to end it with a skip or a failure. */
class Stop extends Error {
  readonly outcome: Outcome;
  constructor(outcome: Outcome) {
    super(outcome.kind);
    this.outcome = outcome;
  }
}

const pidAlive = (pid: number): boolean => {
  if (pid === process.pid) return true;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return errCode(err) === "EPERM"; // it exists, we just may not signal it
  }
};

/** Delete `<file>.av-scrub-*` temp files a crashed scrub left behind. */
async function removeStaleTemps(file: string): Promise<void> {
  const dir = path.dirname(file);
  const prefix = `${path.basename(file)}.av-scrub-`;
  let names: string[];
  try {
    names = await fs.promises.readdir(dir);
  } catch {
    return;
  }
  for (const name of names) {
    const match = name.startsWith(prefix)
      ? /^(\d+)-[0-9a-f]{8}$/.exec(name.slice(prefix.length))
      : null;
    if (!match) continue;
    const leftover = path.join(dir, name);
    try {
      const st = await fs.promises.lstat(leftover);
      if (!st.isFile()) continue;
      if (!pidAlive(Number(match[1])) || Date.now() - st.mtimeMs > STALE_TEMP_MS) {
        await fs.promises.rm(leftover, { force: true });
      }
    } catch {
      // gone already, or not ours to delete: leave it
    }
  }
}

async function scrubOne(
  file: string,
  secrets: { name: string; value: string }[],
  { rename = fs.promises.rename, platform = process.platform, beforeFinalCheck }: ScrubOptions,
): Promise<Outcome> {
  let linkStat: fs.Stats;
  try {
    linkStat = await fs.promises.lstat(file);
  } catch (err) {
    return isGone(err) ? { kind: "missing" } : { kind: "failed", reason: errCode(err) };
  }
  if (linkStat.isSymbolicLink()) return { kind: "skipped", reason: "symlink" };
  if (!linkStat.isFile()) return { kind: "skipped", reason: "not a regular file" };
  // A rename would silently break the link: the other names would keep the old, unscrubbed file.
  if (linkStat.nlink > 1) return { kind: "skipped", reason: "hard link" };
  await removeStaleTemps(file);

  let src: fs.promises.FileHandle | undefined;
  let out: fs.promises.FileHandle | undefined;
  const tmp = `${file}.av-scrub-${process.pid}-${randomBytes(4).toString("hex")}`;
  let renamed = false;
  try {
    try {
      src = await fs.promises.open(file, "r");
    } catch (err) {
      return isGone(err) ? { kind: "missing" } : { kind: "failed", reason: errCode(err) };
    }
    const source = src;
    const opened = await source.stat();
    // The path could have been swapped for something else between `lstat` and `open`.
    if (!opened.isFile() || (platform !== "win32" && opened.ino !== linkStat.ino)) {
      return { kind: "skipped", reason: "not a regular file" };
    }
    try {
      out = await fs.promises.open(tmp, "wx", opened.mode & 0o777);
    } catch (err) {
      if (UNWRITABLE_CODES.has(errCode(err))) {
        return { kind: "skipped", reason: "directory is not writable" };
      }
      throw err;
    }
    const sink = out;

    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
    const scrubber = createBlockScrubber(secrets);
    const buf = Buffer.allocUnsafe(CHUNK_BYTES);
    let offset = 0;
    /** Text read but not yet scrubbed: a partial last line, or lines that may start a multi-line secret. */
    let pending = "";

    const handle = async (text: string, final: boolean): Promise<void> => {
      let cut: number;
      if (final) cut = pending.length + text.length;
      else {
        const newline = text.lastIndexOf("\n");
        if (newline === -1) {
          pending += text;
          if (pending.length > MAX_LINE_CHARS) {
            throw new Stop({ kind: "failed", reason: "line too large" });
          }
          return;
        }
        cut = pending.length + newline + 1;
      }
      const all = pending + text;
      if (!final) cut = scrubber.holdFrom(all, cut);
      pending = all.slice(cut);
      if (pending.length > MAX_LINE_CHARS)
        throw new Stop({ kind: "failed", reason: "line too large" });
      if (cut === 0) return;
      const scrubbed = scrubber.scrubBlock(all.slice(0, cut));
      if (scrubbed !== "") await sink.writeFile(scrubbed);
    };
    /** Stream everything from `offset` to the current end of the file through the scrubber. */
    const pump = async (): Promise<void> => {
      for (;;) {
        const { bytesRead } = await source.read(buf, 0, CHUNK_BYTES, offset);
        if (bytesRead === 0) return;
        offset += bytesRead;
        let text: string;
        try {
          text = decoder.decode(buf.subarray(0, bytesRead), { stream: true });
        } catch {
          throw new Stop({ kind: "skipped", reason: "not valid UTF-8" });
        }
        await handle(text, false);
      }
    };
    /** Read until the size has not moved for one check STABLE_CHECK_MS after the last EOF. */
    const readUntilStable = async (): Promise<fs.Stats> => {
      await pump();
      let last = opened;
      for (let loop = 0; loop < MAX_STABLE_LOOPS; loop++) {
        await sleep(STABLE_CHECK_MS);
        last = await source.stat();
        if (last.size < offset) throw new Stop({ kind: "failed", reason: "file was truncated" });
        if (last.size === offset) return last;
        await pump();
      }
      throw new Stop({ kind: "failed", reason: "file kept growing" });
    };
    /** Scrub what is still pending as if the file ended here. */
    const finish = async (): Promise<void> => {
      let rest: string;
      try {
        rest = decoder.decode();
      } catch {
        // Half a character at the end: a writer is probably mid-write. Try again later.
        throw new Stop({ kind: "failed", reason: "file ends inside a character" });
      }
      await handle(rest, true);
    };

    // Append safety (Review Focus 3): the harness may still be writing. Read until the size is
    // stable, finish and fsync, then look once more: bytes that arrived meanwhile send us back.
    let last = opened;
    for (let round = 0; ; round++) {
      last = await readUntilStable();
      await finish();
      if (scrubber.matchCount() === 0) return { kind: "clean" };
      await sink.sync();
      await beforeFinalCheck?.();
      if ((await source.stat()).size === offset) break;
      if (round + 1 >= MAX_FINAL_ROUNDS)
        throw new Stop({ kind: "failed", reason: "file kept growing" });
    }
    const replacements = scrubber.matchCount();

    // Same permissions and modification time, so the harness's session list does not reorder.
    await sink.chmod(opened.mode & 0o777);
    await sink.utimes(last.atime, (await source.stat()).mtime);
    await sink.close();
    out = undefined;
    await source.close();
    src = undefined;

    // Accepted window: a line appended after the size check above and before this rename goes to
    // the old inode and is lost. The check, the two closes and the rename take milliseconds, and
    // the harnesses append open-write-close per line (S3), so a loss needs a line to land there.
    try {
      await renameWithRetry(rename, tmp, file, platform === "win32");
    } catch (err) {
      return { kind: "failed", reason: errCode(err) };
    }
    renamed = true;
    return { kind: "changed", replacements };
  } catch (err) {
    if (err instanceof Stop) return err.outcome;
    if (err instanceof JsonCorruptionError) return { kind: "failed", reason: err.message };
    return isGone(err) ? { kind: "missing" } : { kind: "failed", reason: errCode(err) };
  } finally {
    await out?.close().catch(() => {});
    await src?.close().catch(() => {});
    if (!renamed) await fs.promises.rm(tmp, { force: true }).catch(() => {});
  }
}

/**
 * Replace every copy of each secret in `files` with its `vault://name` reference (raw, base64,
 * base64url, URL-encoded and JSON-escaped forms; see the detect redactor). Each file is rewritten
 * through a temp file in its own directory and renamed over the original, so a reader sees the old
 * or the new file, never a mix. A file with no match is not touched. Bytes the harness appends
 * while the scrub runs are read, redacted and kept (see `scrubOne`).
 *
 * Never throws for a file; the outcome of each is in the result. Never puts a value in it. The
 * secret strings stay in memory for the call, since JavaScript cannot zero a string.
 */
export async function scrubFiles(
  files: string[],
  replacements: Replacement[],
  opts: ScrubOptions = {},
): Promise<ScrubResult> {
  const secrets = replacements.map((r) => ({
    name: r.ref.startsWith(REF_PREFIX) ? r.ref.slice(REF_PREFIX.length) : r.ref,
    value: r.value,
  }));
  const result: ScrubResult = { filesChanged: 0, replacements: 0, skipped: [], failed: [] };
  if (secrets.length === 0) return result;
  for (const file of new Set(files)) {
    const outcome = await scrubOne(file, secrets, opts);
    if (outcome.kind === "changed") {
      result.filesChanged++;
      result.replacements += outcome.replacements;
    } else if (outcome.kind === "skipped") {
      result.skipped.push({ file, reason: outcome.reason });
    } else if (outcome.kind === "failed") {
      result.failed.push({ file, reason: outcome.reason });
    }
  }
  return result;
}
