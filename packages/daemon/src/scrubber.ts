import { randomBytes } from "node:crypto";
import fs from "node:fs";
import { setTimeout as sleep } from "node:timers/promises";
import { createRedactor } from "@agent-vault/detect";

/** How much of a file is read, redacted and written at a time. */
const CHUNK_BYTES = 64 * 1024;
/** The gap between the size checks that decide the file has stopped growing. */
const STABLE_CHECK_MS = 50;
const MAX_STABLE_LOOPS = 20;
/** Windows refuses to replace a file another process has open; try again for a moment. */
const RENAME_ATTEMPTS = 5;
const RENAME_BACKOFF_MS = 100;
const RENAME_RETRY_CODES: ReadonlySet<string> = new Set(["EPERM", "EBUSY", "EACCES"]);
const REF_PREFIX = "vault://";

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
  /** Files that were deliberately not touched (symlink, not a regular file, not UTF-8). */
  skipped: FileProblem[];
  /** Files that should be tried again later (rename refused, kept growing, I/O error). */
  failed: FileProblem[];
};

export type ScrubOptions = {
  /** Replaces `fs.promises.rename`; tests make it fail. */
  rename?: (from: string, to: string) => Promise<void>;
  /** Replaces `process.platform`; only `win32` retries a refused rename. */
  platform?: NodeJS.Platform;
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

async function scrubOne(
  file: string,
  secrets: { name: string; value: string }[],
  { rename = fs.promises.rename, platform = process.platform }: ScrubOptions,
): Promise<Outcome> {
  let linkStat: fs.Stats;
  try {
    linkStat = await fs.promises.lstat(file);
  } catch (err) {
    return isGone(err) ? { kind: "missing" } : { kind: "failed", reason: errCode(err) };
  }
  if (linkStat.isSymbolicLink()) return { kind: "skipped", reason: "symlink" };
  if (!linkStat.isFile()) return { kind: "skipped", reason: "not a regular file" };

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
    const opened = await src.stat();
    // The path could have been swapped for something else between `lstat` and `open`.
    if (!opened.isFile() || (platform !== "win32" && opened.ino !== linkStat.ino)) {
      return { kind: "skipped", reason: "not a regular file" };
    }
    out = await fs.promises.open(tmp, "wx", opened.mode & 0o777);

    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
    const redactor = createRedactor(secrets, { marker: (name) => `${REF_PREFIX}${name}` });
    const buf = Buffer.allocUnsafe(CHUNK_BYTES);
    let offset = 0;

    const push = async (text: string): Promise<void> => {
      const redacted = redactor.push(text);
      if (redacted !== "") await out?.writeFile(redacted);
    };
    /** Stream everything from `offset` to the current end of the file through the redactor. */
    const pump = async (): Promise<void> => {
      for (;;) {
        const { bytesRead } = await (src as fs.promises.FileHandle).read(
          buf,
          0,
          CHUNK_BYTES,
          offset,
        );
        if (bytesRead === 0) return;
        offset += bytesRead;
        let text: string;
        try {
          text = decoder.decode(buf.subarray(0, bytesRead), { stream: true });
        } catch {
          throw new Stop({ kind: "skipped", reason: "not valid UTF-8" });
        }
        await push(text);
      }
    };

    // Append safety (Review Focus 3): the harness may still be writing. Keep reading until the
    // size has not moved for one check STABLE_CHECK_MS after the last EOF, then swap the files.
    await pump();
    let stable = false;
    let last = opened;
    for (let loop = 0; loop < MAX_STABLE_LOOPS && !stable; loop++) {
      await sleep(STABLE_CHECK_MS);
      last = await src.stat();
      if (last.size < offset) throw new Stop({ kind: "failed", reason: "file was truncated" });
      if (last.size === offset) stable = true;
      else await pump();
    }
    if (!stable) throw new Stop({ kind: "failed", reason: "file kept growing" });

    let rest: string;
    try {
      rest = decoder.decode(); // a file that ends inside a multi-byte character throws here
    } catch {
      throw new Stop({ kind: "skipped", reason: "not valid UTF-8" });
    }
    await push(rest);
    const tail = redactor.flush();
    if (tail !== "") await out.writeFile(tail);
    const replacements = redactor.matchCount();
    if (replacements === 0) return { kind: "clean" };

    // Same permissions and modification time, so the harness's session list does not reorder.
    await out.chmod(opened.mode & 0o777);
    await out.utimes(last.atime, last.mtime);
    await out.sync();
    await out.close();
    out = undefined;
    await src.close();
    src = undefined;

    // Accepted window: a line appended after the last size check and before this rename goes to
    // the old inode and is lost. The harnesses append open-write-close per line (S3), so the
    // window is the few microseconds between the check and the rename.
    try {
      await renameWithRetry(rename, tmp, file, platform === "win32");
    } catch (err) {
      return { kind: "failed", reason: errCode(err) };
    }
    renamed = true;
    return { kind: "changed", replacements };
  } catch (err) {
    if (err instanceof Stop) return err.outcome;
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
