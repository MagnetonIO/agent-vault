import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { detectSecrets, fingerprint } from "@agent-vault/detect";

const run = promisify(execFile);

/** Marks a hook as ours, so install and uninstall never touch someone else's. */
export const HOOK_MARKER = "# agent-vault guard hook";
/** Where an existing pre-commit hook is kept, and still run, while ours is installed. */
export const CHAINED_HOOK = "pre-commit.agent-vault-orig";

export type GuardHit = { file: string; line: number; fingerprint: string };

const VAULT_REF_RE = /vault:\/\/[a-z0-9._/-]*/g;

/**
 * Secrets on the lines a unified diff (`-U0`) adds. `vault://` references are blanked first. Only
 * fingerprints are returned, never a value.
 */
export function scanDiff(diff: string): GuardHit[] {
  const hits: GuardHit[] = [];
  let file = "";
  let line = 0;
  // `+++ ` is a file header only before a diff's first hunk; inside one it is an added line.
  let inHeader = false;
  for (const raw of diff.split(/\r?\n/)) {
    if (raw.startsWith("diff ")) {
      inHeader = true;
      file = "";
    } else if (inHeader && raw.startsWith("+++ ")) {
      // git adds a tab after names that hold spaces.
      const target = raw.slice(4).replace(/\t.*$/, "").replace(/^"|"$/g, "");
      file = target === "/dev/null" ? "" : target.replace(/^b\//, "");
    } else if (raw.startsWith("@@")) {
      inHeader = false;
      line = Number(/\+(\d+)/.exec(raw)?.[1] ?? 0);
    } else if (!inHeader && raw.startsWith("+") && file !== "") {
      for (const d of detectSecrets(raw.slice(1).replace(VAULT_REF_RE, ""))) {
        hits.push({ file, line, fingerprint: fingerprint(d) });
      }
      line++;
    }
  }
  return hits;
}

async function git(cwd: string, args: string[]): Promise<string> {
  try {
    const { stdout } = await run("git", args, {
      cwd,
      encoding: "utf8",
      maxBuffer: 512 * 1024 * 1024,
      windowsHide: true,
    });
    return stdout;
  } catch (err) {
    const stderr = String((err as { stderr?: unknown }).stderr ?? "").trim();
    const subcommand = args.find((a, i) => !a.startsWith("-") && args[i - 1] !== "-c") ?? "git";
    throw new Error(`git ${subcommand} failed${stderr ? `: ${stderr.split("\n")[0]}` : ""}`);
  }
}

/** Check what is staged (or, without `staged`, the working tree) for added secrets. */
export async function checkDiff(opts: { cwd: string; staged: boolean }): Promise<GuardHit[]> {
  await git(opts.cwd, ["rev-parse", "--git-dir"]); // outside a repo, `git diff` would diff two paths
  const args = [
    "-c",
    "core.quotepath=off",
    "diff",
    "-U0",
    "--no-color",
    "--no-ext-diff",
    "--no-textconv",
  ];
  if (opts.staged) args.push("--cached");
  return scanDiff(await git(opts.cwd, args));
}

async function hooksDir(cwd: string): Promise<string> {
  const out = (await git(cwd, ["rev-parse", "--git-path", "hooks"])).trim();
  return path.resolve(cwd, out);
}

/** A path for a `sh` script: forward slashes, which Git for Windows' sh reads too. */
const shQuote = (s: string): string => `"${s.replace(/\\/g, "/").replace(/(["$`])/g, "\\$1")}"`;

function hookScript(command: string[]): string {
  return [
    "#!/bin/sh",
    `${HOOK_MARKER} (remove with: agent-vault guard uninstall)`,
    `${command.map(shQuote).join(" ")} guard check --staged || exit 1`,
    `chained="$(dirname "$0")/${CHAINED_HOOK}"`,
    `if [ -f "$chained" ]; then exec "$chained" "$@"; fi`,
    "",
  ].join("\n");
}

export type HookResult = { hook: string; chained: string | null };

/**
 * Write `<git-dir>/hooks/pre-commit` so `guard check --staged` runs before every commit. A hook
 * that is already there is moved to `pre-commit.agent-vault-orig` and runs after ours.
 * `command` is how the hook starts agent-vault (a program and leading arguments).
 */
export async function installHook(opts: { cwd: string; command?: string[] }): Promise<HookResult> {
  const dir = await hooksDir(opts.cwd);
  const hook = path.join(dir, "pre-commit");
  const chained = path.join(dir, CHAINED_HOOK);
  fs.mkdirSync(dir, { recursive: true });

  let kept: string | null = null;
  if (fs.existsSync(hook) && !fs.readFileSync(hook, "utf8").includes(HOOK_MARKER)) {
    if (fs.existsSync(chained)) {
      throw new Error(`${hook} is not ours and ${chained} already exists; resolve that first`);
    }
    fs.renameSync(hook, chained);
    kept = chained;
  } else if (fs.existsSync(chained)) {
    kept = chained;
  }
  fs.writeFileSync(hook, hookScript(opts.command ?? ["agent-vault"]), { mode: 0o755 });
  fs.chmodSync(hook, 0o755);
  return { hook, chained: kept };
}

/** Remove our hook and put the original back, byte for byte. False if ours was not installed. */
export async function uninstallHook(opts: { cwd: string }): Promise<boolean> {
  const dir = await hooksDir(opts.cwd);
  const hook = path.join(dir, "pre-commit");
  const chained = path.join(dir, CHAINED_HOOK);
  if (!fs.existsSync(hook) || !fs.readFileSync(hook, "utf8").includes(HOOK_MARKER)) return false;
  if (fs.existsSync(chained)) fs.renameSync(chained, hook);
  else fs.rmSync(hook);
  return true;
}
