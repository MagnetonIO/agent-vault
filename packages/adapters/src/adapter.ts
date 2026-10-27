/**
 * What every harness adapter (Claude Code, Codex, OpenCode) implements. The CLI's `install`,
 * `uninstall`, `doctor` and `hook` commands only talk to this.
 */

export type HarnessId = "claude-code" | "codex" | "opencode";

export type InstallOptions = {
  home: string;
  /**
   * The name of a secret to use as the harness's own model key (`apiKeyHelper` for Claude Code).
   * It must exist and carry the `helper` tag.
   */
  modelKey?: string | undefined;
};

export type InstallReport = {
  harness: HarnessId;
  /** Files that were changed or created. */
  files: string[];
  /** Copies of the files before the change. They hold whatever the originals held. */
  backups: string[];
  /** One line each for a person: what was done, and what was left alone or needs a step. */
  notes: string[];
  /** Things that work now but may stop working; shown on stderr. */
  warnings?: string[] | undefined;
};

export type DoctorCheck = {
  name: string;
  ok: boolean;
  detail: string;
  /** A line to read, not a test: `ok` is true and `doctor` prints it without counting it. */
  info?: boolean | undefined;
  /** What to run when `ok` is false. */
  fix?: string | undefined;
  /** The check passes, but something may stop it from passing later. */
  warning?: string | undefined;
};

export type DoctorReport = {
  harness: HarnessId;
  /** True if every check is. */
  ok: boolean;
  checks: DoctorCheck[];
};

/** The JSON the harness expects on stdout, or `null` to print nothing (allow). */
export type HookOutput = Record<string, unknown> | null;

export type HookOptions = {
  /**
   * Detection only: report a block for a prompt that holds a key, store nothing, never contact
   * the daemon. `doctor` uses it to prove the installed hook runs.
   */
  probe?: boolean | undefined;
};

export interface HarnessAdapter {
  readonly id: HarnessId;
  /** True if the harness has a config under `home`. */
  detect(home: string): Promise<boolean>;
  install(opts: InstallOptions): Promise<InstallReport>;
  /** Remove what `install` added. Anything else in the harness's files stays. */
  uninstall(home: string): Promise<void>;
  doctor(home: string): Promise<DoctorReport>;
  /**
   * One hook event, as the harness sends it (`input` is its stdin, parsed). Resolves to what to
   * print. It must not throw for a prompt without a key: a crash there must let the prompt through.
   */
  handleHook(event: string, input: unknown, opts?: HookOptions): Promise<HookOutput>;
  /**
   * The harness's JSON for blocking a prompt with this reason. The CLI uses it where the adapter
   * cannot run (a prompt too large to read): a prompt that cannot be checked must not go through.
   */
  blockOutput(reason: string): HookOutput;
  /** Files that can hold what the user typed: the harness's history, and `input`'s transcript. */
  historyFiles(home: string, input?: unknown): string[];
}

/** A failure the user can act on. The CLI prints the message and exits 1. */
export class AdapterError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AdapterError";
  }
}
