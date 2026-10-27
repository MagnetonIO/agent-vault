import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  appendAudit,
  deleteScrubRows,
  enqueueScrub,
  isValidName,
  listScrubQueue,
  type ScrubRow,
  SecretNotFoundError,
  type Vault,
} from "@agent-vault/core";
import { deviceId, HARNESSES, type Harness } from "../device.js";
import { SecretNotTextError } from "../errors.js";
import { type FileProblem, type ScrubOptions, scrubFiles } from "../scrubber.js";
import { decodeSecretText } from "../secret-text.js";
import { invalid, paramsObject } from "./params.js";
import type { Registry } from "./types.js";

/** Same floor as the redactor: shorter values cannot be replaced without mangling ordinary text. */
const MIN_SCRUB_LENGTH = 4;
const MAX_FILES = 1000;
const MAX_NAMES = 100;

/** The nearest existing ancestor's real path with the rest of `dir` appended. */
function realDir(dir: string): string {
  const tail: string[] = [];
  for (let cur = dir; ; cur = path.dirname(cur)) {
    try {
      return path.join(fs.realpathSync.native(cur), ...tail);
    } catch {
      const parent = path.dirname(cur);
      if (parent === cur) return dir;
      tail.unshift(path.basename(cur));
    }
  }
}

/**
 * True if `file` is absolute and, once the symlinks in its directory are resolved, lies under the
 * user's home. The home is `os.homedir()`, which follows `HOME` (`USERPROFILE` on Windows), so a
 * test sandbox only has to set those. A file that does not exist yet is judged by its directory.
 */
function underHome(file: string): boolean {
  if (!path.isAbsolute(file) || file.includes("\0")) return false;
  let home: string;
  try {
    home = fs.realpathSync.native(os.homedir());
  } catch {
    return false;
  }
  const resolved = path.resolve(file);
  const real = path.join(realDir(path.dirname(resolved)), path.basename(resolved));
  const rel = path.relative(home, real);
  return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
}

function reqHarness(p: Record<string, unknown>): Harness {
  const h = p.harness;
  if (!(HARNESSES as readonly unknown[]).includes(h)) {
    throw invalid("harness", "must be a known harness");
  }
  return h as Harness;
}

function stringArray(v: unknown, field: string, max: number): string[] {
  if (
    !Array.isArray(v) ||
    v.length === 0 ||
    v.length > max ||
    v.some((x) => typeof x !== "string" || x.length === 0)
  ) {
    throw invalid(field, `must be a list of 1 to ${max} non-empty strings`);
  }
  return v as string[];
}

/** One `scrub.run` at a time per vault: two scrubs of one file would race on its temp file. */
const running = new WeakMap<Vault, Promise<unknown>>();
function exclusive<T>(vault: Vault, job: () => Promise<T>): Promise<T> {
  const run = (running.get(vault) ?? Promise.resolve()).then(job, job);
  running.set(
    vault,
    run.catch(() => {}),
  );
  return run;
}

type Dropped = { secret: string; reason: "removed" | "too short" | "not text" };

/**
 * The text of each secret in `names`, or why it cannot be scrubbed. The decrypted bytes are zeroed
 * at once; the strings the redactor needs live until the run ends (JavaScript cannot zero them).
 */
function loadValues(
  vault: Vault,
  names: Iterable<string>,
): { values: Map<string, string>; dropped: Dropped[] } {
  const values = new Map<string, string>();
  const dropped: Dropped[] = [];
  for (const name of names) {
    try {
      const bytes = vault.readValue(name);
      try {
        const value = decodeSecretText(name, bytes);
        if (value.length < MIN_SCRUB_LENGTH) dropped.push({ secret: name, reason: "too short" });
        else values.set(name, value);
      } finally {
        bytes.fill(0);
      }
    } catch (err) {
      if (err instanceof SecretNotFoundError) dropped.push({ secret: name, reason: "removed" });
      else if (err instanceof SecretNotTextError)
        dropped.push({ secret: name, reason: "not text" });
      else throw err;
    }
  }
  return { values, dropped };
}

function auditScrubbed(vault: Vault, harness: Harness, names: string[]): void {
  for (const secretName of names) {
    appendAudit(vault, {
      deviceId,
      harness,
      actor: "rpc",
      secretName,
      operation: "scrub",
      outcome: "captured",
    });
  }
}

async function runQueue(vault: Vault, harness: Harness, scrubOpts: ScrubOptions) {
  const rows = listScrubQueue(vault, harness);
  const byFile = new Map<string, ScrubRow[]>();
  for (const row of rows) byFile.set(row.file, [...(byFile.get(row.file) ?? []), row]);

  const { values, dropped } = loadValues(vault, new Set(rows.map((r) => r.secretName)));
  const skipped: FileProblem[] = [];
  const failed: FileProblem[] = [];
  let filesChanged = 0;
  let replacements = 0;

  for (const [file, fileRows] of byFile) {
    const names = [...new Set(fileRows.map((r) => r.secretName))].filter((n) => values.has(n));
    let retry = false;
    if (names.length > 0) {
      if (!underHome(file)) {
        skipped.push({ file, reason: "outside the home directory" });
      } else {
        const result = await scrubFiles(
          [file],
          names.map((name) => ({ value: values.get(name) as string, ref: name })),
          scrubOpts,
        );
        filesChanged += result.filesChanged;
        replacements += result.replacements;
        skipped.push(...result.skipped);
        failed.push(...result.failed);
        retry = result.failed.length > 0;
        if (result.filesChanged > 0) auditScrubbed(vault, harness, names);
      }
    }
    if (!retry)
      deleteScrubRows(
        vault,
        fileRows.map((r) => r.id),
      );
  }
  // Rows of a secret that cannot be scrubbed at all would sit in the queue for ever.
  const gone = new Set(dropped.map((d) => d.secret));
  deleteScrubRows(
    vault,
    rows.filter((r) => gone.has(r.secretName)).map((r) => r.id),
  );

  return {
    filesChanged,
    replacements,
    skipped,
    failed,
    dropped,
    remaining: listScrubQueue(vault, harness).length,
  };
}

/** The `scrub.*` methods. `scrubOpts` lets tests fail the rename or pose as Windows. */
export const createScrubMethods = (scrubOpts: ScrubOptions = {}): Registry => ({
  "scrub.queue": {
    mutates: true,
    returnsSecret: false,
    handler: (ctx, params) => {
      const p = paramsObject(params, ["harness", "files", "secretNames"]);
      const harness = reqHarness(p);
      const files = stringArray(p.files, "files", MAX_FILES);
      const secretNames = stringArray(p.secretNames, "secretNames", MAX_NAMES);
      if (!files.every(underHome)) {
        throw invalid("files", "must be absolute paths under the home directory");
      }
      if (!secretNames.every(isValidName)) throw invalid("secretNames", "must be valid names");
      const vault = ctx.vault();
      for (const name of secretNames) {
        if (!vault.has(name)) throw new SecretNotFoundError(name);
      }
      if (secretNames.length === 1) ctx.audit.secretName = secretNames[0];
      const entries = [...new Set(files.map((f) => path.resolve(f)))].flatMap((file) =>
        [...new Set(secretNames)].map((secretName) => ({ file, secretName })),
      );
      return { queued: enqueueScrub(vault, harness, entries) };
    },
  },
  "scrub.run": {
    mutates: true,
    returnsSecret: false,
    handler: (ctx, params) => {
      const harness = reqHarness(paramsObject(params, ["harness"]));
      const vault = ctx.vault();
      return exclusive(vault, () => runQueue(vault, harness, scrubOpts));
    },
  },
});

export const scrubMethods: Registry = createScrubMethods();
