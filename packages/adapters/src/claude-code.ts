import { spawn } from "node:child_process";
import { randomInt } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { getPaths } from "@agent-vault/platform";
import {
  AdapterError,
  type DoctorCheck,
  type DoctorReport,
  type HarnessAdapter,
  type HookOptions,
  type HookOutput,
  type InstallOptions,
  type InstallReport,
} from "./adapter.js";
import { backupFile, writeFileAtomic } from "./backup.js";
import { claudeConfigDir, claudeGlobalFile } from "./config-dirs.js";
import { type HookClient, handlePromptSubmit, handleScrub } from "./hook.js";
import {
  addHooksTracked,
  findHooks,
  type HookSpec,
  quoteCommand,
  removeHooks,
  splitCommand,
} from "./hook-config.js";
import { type FileState, loadState, pruneFrom, saveState } from "./install-state.js";
import {
  JsonEditError,
  type JsonPath,
  missingContainers,
  parseJson,
  removeAt,
  setAt,
} from "./json-edit.js";
import { wrappedServersCheck } from "./wrapped-check.js";

/** What follows our command words in every hook command we write. */
export const CLAUDE_HOOK_MARKER = " hook claude-code ";

/**
 * Directories a version manager keeps its Node versions in. A hook that runs `node` from there
 * stops working, silently, when that version is removed.
 */
const VERSION_MANAGER_RE =
  /[\\/](\.?fnm|fnm_multishells|\.?nvm|\.asdf|\.volta|\.nodenv|\.?mise|Cellar)[\\/]/i;

/** The version manager whose directory holds `file`, if any. */
export function versionManagerOf(file: string): string | undefined {
  return VERSION_MANAGER_RE.exec(file)?.[1]?.replace(/^\./, "");
}
const MCP_NAME = "agent-vault";
const PROMPT_TIMEOUT_S = 30;
const SCRUB_TIMEOUT_S = 15;
const PROBE_TIMEOUT_MS = 15_000;
const CLAUDE_TIMEOUT_MS = 30_000;
/** Shown by a failed `--model-key`. */
export const tagFirst = (name: string): string =>
  `tag it first: agent-vault set ${name} --tag helper`;

/** Runs `claude <args>` (no shell). `code` is null if the binary is absent or could not start. */
export type ClaudeRunner = (args: string[]) => Promise<{ code: number | null }>;

/** Runs a hook command line through a shell, as Claude does, with `stdin` on its input. */
export type ProbeRunner = (
  command: string,
  stdin: string,
) => Promise<{ code: number | null; stdout: string }>;

export type ClaudeCodeDeps = {
  /** How to run agent-vault, as absolute words: `[node, main.js]`, or the single-file binary. */
  command: string[];
  /** Connects to the daemon. */
  client: () => Promise<HookClient>;
  /** The user's home. Default `os.homedir()`. */
  home?: string | undefined;
  /** Default `process.env`; `CLAUDE_CONFIG_DIR` and (for `doctor`) PATH are read from it. */
  env?: NodeJS.ProcessEnv | undefined;
  /** Default `getPaths().backupsDir`. */
  backupsDir?: string | undefined;
  /** What an install records for its uninstall. Default `<dataDir>/adapters/claude-code-state.json`. */
  stateFile?: string | undefined;
  /** Overall deadline of the prompt hook; see `HOOK_DEADLINE_MS`. */
  deadlineMs?: number | undefined;
  /** Default: spawn `claude` from PATH. Tests inject one: they must never run the real binary. */
  runClaude?: ClaudeRunner | undefined;
  /** Default: spawn the command in a shell. */
  runProbe?: ProbeRunner | undefined;
  platform?: NodeJS.Platform | undefined;
  /** For stderr. */
  log?: ((message: string) => void) | undefined;
};

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

function defaultRunClaude(env: NodeJS.ProcessEnv): ClaudeRunner {
  return (args) =>
    new Promise((resolve) => {
      const child = spawn("claude", args, {
        stdio: "ignore",
        env,
        windowsHide: true,
        timeout: CLAUDE_TIMEOUT_MS,
      });
      child.once("error", () => resolve({ code: null }));
      child.once("close", (code) => resolve({ code }));
    });
}

export function defaultRunProbe(env: NodeJS.ProcessEnv): ProbeRunner {
  return (command, stdin) =>
    new Promise((resolve) => {
      const child = spawn(command, {
        shell: true,
        env,
        windowsHide: true,
        timeout: PROBE_TIMEOUT_MS,
        stdio: ["pipe", "pipe", "ignore"],
      });
      let stdout = "";
      child.stdout.setEncoding("utf8").on("data", (c: string) => (stdout += c));
      child.stdin.on("error", () => {});
      child.stdin.end(stdin);
      child.once("error", () => resolve({ code: null, stdout }));
      child.once("close", (code) => resolve({ code, stdout }));
    });
}

/** A key-shaped value made now, so no key-like literal exists in the source. */
export function fakeKey(): string {
  const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let body = "";
  for (let i = 0; i < 36; i++) body += alnum[randomInt(alnum.length)];
  return `gh${"p"}_${body}`;
}

export function createClaudeCodeAdapter(deps: ClaudeCodeDeps): HarnessAdapter {
  const env = deps.env ?? process.env;
  const platform = deps.platform ?? process.platform;
  const runClaude = deps.runClaude ?? defaultRunClaude(env);
  const runProbe = deps.runProbe ?? defaultRunProbe(env);
  const log = deps.log ?? (() => {});
  const homeDir = (): string => deps.home ?? os.homedir();
  const backupsDir = (): string => deps.backupsDir ?? getPaths().backupsDir;

  const configDir = (home: string): string => claudeConfigDir(home, env.CLAUDE_CONFIG_DIR);
  const settingsFile = (home: string): string => path.join(configDir(home), "settings.json");
  /** Claude keeps its user-scope config (MCP servers) beside the config dir, or inside it. */
  const globalFile = (home: string): string => claudeGlobalFile(home, env.CLAUDE_CONFIG_DIR);

  const words = (...extra: string[]): string => quoteCommand([...deps.command, ...extra], platform);
  const hookSpecs = (): HookSpec[] => [
    {
      event: "UserPromptSubmit",
      command: words("hook", "claude-code", "prompt-submit"),
      timeout: PROMPT_TIMEOUT_S,
    },
    {
      event: "SessionEnd",
      command: words("hook", "claude-code", "scrub"),
      timeout: SCRUB_TIMEOUT_S,
    },
    {
      event: "SessionStart",
      command: words("hook", "claude-code", "scrub"),
      timeout: SCRUB_TIMEOUT_S,
    },
  ];
  const helperCommand = (secret: string): string => words("helper", secret);
  /** The command words this adapter writes now, quoted. */
  const prefix = (): string => quoteCommand(deps.command, platform);
  const stateFile = (): string =>
    deps.stateFile ?? path.join(getPaths().dataDir, "adapters", "claude-code-state.json");
  /**
   * Entries are ours only if they start with the command words an install wrote: the ones it
   * would write now, or the ones it recorded (the binary may have moved since). A command that
   * merely mentions `hook claude-code`, or a foreign `node ... helper prod`, is not.
   */
  const prefixesOf = (recorded: FileState | undefined): string[] => [
    ...new Set([prefix(), ...(recorded ? [recorded.prefix] : [])]),
  ];
  const isOurHook =
    (prefixes: string[]) =>
    (command: string): boolean =>
      prefixes.some((p) => command.startsWith(`${p}${CLAUDE_HOOK_MARKER}`));
  const isOurHelper = (value: unknown, prefixes: string[]): boolean =>
    typeof value === "string" &&
    prefixes.some(
      (p) =>
        value.startsWith(`${p} helper `) &&
        /^[a-z0-9][a-z0-9._/-]*$/.test(value.slice(p.length + 8)),
    );
  const mcpEntry = (): { type: string; command: string; args: string[] } => ({
    type: "stdio",
    command: deps.command[0] as string,
    args: [...deps.command.slice(1), "mcp"],
  });

  const read = (file: string): string | null => {
    try {
      return fs.readFileSync(file, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  };

  /** The parsed file, or an `AdapterError` naming it if it is not JSON. Absent is `{}`. */
  const parsed = (file: string, text: string | null): Record<string, unknown> => {
    try {
      return text === null ? {} : parseJson(text);
    } catch (err) {
      const why = err instanceof JsonEditError ? err.message : String(err);
      throw new AdapterError(`${file} is not usable (${why}); fix it by hand first`);
    }
  };

  const write = (file: string, text: string, backups: string[], existed: boolean): void => {
    if (existed) {
      backups.push(backupFile(file, backupsDir()));
      writeFileAtomic(file, text);
    } else {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, text, { mode: 0o600 });
    }
  };

  /** What to record about a file we are about to change. */
  const stateFor = (
    text: string | null,
    previous: FileState | undefined,
    created: JsonPath[],
  ): FileState => {
    const whitespace = text !== null && text.trim() === "" ? text : previous?.whitespace;
    return {
      createdFile: text === null || (previous?.createdFile ?? false),
      ...(whitespace !== undefined && { whitespace }),
      created,
      prefix: prefix(),
    };
  };

  /** Save `next` over `file`, or take the file away if we made it and nothing else is in it. */
  const finish = (file: string, next: string, recorded: FileState | undefined): void => {
    const bare = Object.keys(parseJson(next)).length === 0;
    if (bare && recorded?.createdFile) fs.rmSync(file, { force: true });
    else if (bare && recorded?.whitespace !== undefined) writeFileAtomic(file, recorded.whitespace);
    else writeFileAtomic(file, next);
  };

  const mcpOf = (root: Record<string, unknown>): Record<string, unknown> | undefined => {
    const entry = isRecord(root.mcpServers) ? root.mcpServers[MCP_NAME] : undefined;
    return isRecord(entry) ? entry : undefined;
  };
  const sameMcp = (entry: Record<string, unknown>): boolean => {
    const want = mcpEntry();
    return (
      entry.command === want.command &&
      Array.isArray(entry.args) &&
      entry.args.length === want.args.length &&
      entry.args.every((a, i) => a === want.args[i])
    );
  };

  function blockOutput(reason: string): HookOutput {
    return {
      decision: "block",
      reason,
      hookSpecificOutput: { hookEventName: "UserPromptSubmit", suppressOriginalPrompt: true },
    };
  }

  const adapter: HarnessAdapter = {
    id: "claude-code",

    async detect(home) {
      return fs.existsSync(configDir(home)) || fs.existsSync(globalFile(home));
    },

    async install({ home, modelKey }: InstallOptions): Promise<InstallReport> {
      // Everything that can refuse comes before the first write.
      if (!path.isAbsolute(deps.command[0] ?? "")) {
        throw new AdapterError(
          "cannot tell where agent-vault is installed: run the built CLI (pnpm build) or the single-file binary",
        );
      }
      if (modelKey !== undefined) {
        const client = await deps.client();
        try {
          const list = await client.call<{ name: string; tags: string[] }[]>("secret.list");
          const meta = list.find((m) => m.name === modelKey);
          if (!meta?.tags.includes("helper")) throw new AdapterError(tagFirst(modelKey));
        } finally {
          client.close();
        }
      }
      const settings = settingsFile(home);
      const settingsText = read(settings);
      const settingsRoot = parsed(settings, settingsText);
      if (!isRecord(settingsRoot.hooks ?? {})) {
        throw new AdapterError(`${settings}: "hooks" is not an object; fix it by hand first`);
      }
      const global = globalFile(home);
      const globalText = read(global);
      const globalRoot = parsed(global, globalText);
      const state = loadState(stateFile());
      const prevSettings = state.files[settings];
      const prevGlobal = state.files[global];
      const prefixes = prefixesOf(prevSettings);
      if (
        modelKey !== undefined &&
        settingsRoot.apiKeyHelper !== undefined &&
        !isOurHelper(settingsRoot.apiKeyHelper, prefixes)
      ) {
        throw new AdapterError(
          `${settings} already sets apiKeyHelper to something else; remove it first, then retry`,
        );
      }

      const report: InstallReport = {
        harness: "claude-code",
        files: [],
        backups: [],
        notes: [],
        warnings: [],
      };
      const manager = versionManagerOf(deps.command[0] as string);
      if (manager) {
        report.warnings?.push(
          `the hooks run ${deps.command[0]}, which belongs to ${manager}: removing or switching that Node version silently disables prompt capture. Run \`agent-vault doctor claude-code\` after upgrading Node, or install the single-file binary.`,
        );
      }

      const { text: hooked, created } = addHooksTracked(
        settingsText ?? "",
        hookSpecs(),
        isOurHook(prefixes),
        pruneFrom(prevSettings),
      );
      let next = hooked;
      if (modelKey !== undefined) next = setAt(next, ["apiKeyHelper"], helperCommand(modelKey));
      // Containers a previous install made and the user has since filled stay recorded.
      for (const path of prevSettings?.created ?? []) {
        if (
          missingContainers(next, path).length === 0 &&
          !created.some((c) => c.join("\0") === path.join("\0"))
        ) {
          created.push(path);
        }
      }
      write(settings, next, report.backups, settingsText !== null);
      state.files[settings] = stateFor(settingsText, prevSettings, created);
      report.files.push(settings);
      report.notes.push("hooks: UserPromptSubmit, SessionEnd, SessionStart");
      if (modelKey !== undefined)
        report.notes.push(`apiKeyHelper reads ${modelKey} from the vault`);

      const existing = mcpOf(globalRoot);
      if (existing && sameMcp(existing)) {
        report.notes.push("MCP server agent-vault was already registered");
        saveState(stateFile(), state);
        return report;
      }
      if (globalText !== null) report.backups.push(backupFile(global, backupsDir()));
      let viaCli = false;
      if (!existing) {
        const run = await runClaude([
          "mcp",
          "add",
          "--scope",
          "user",
          MCP_NAME,
          "--",
          ...deps.command,
          "mcp",
        ]);
        viaCli = run.code === 0;
      }
      if (viaCli) {
        state.files[global] = stateFor(globalText ?? "{}", prevGlobal, []);
        report.notes.push("MCP server agent-vault added with `claude mcp add --scope user`");
      } else {
        // No `claude` on PATH, or it failed: write the entry it would have written.
        const text = setAt(globalText ?? "", ["mcpServers", MCP_NAME], mcpEntry());
        if (globalText !== null) writeFileAtomic(global, text);
        else write(global, text, report.backups, false);
        state.files[global] = stateFor(
          globalText,
          prevGlobal,
          globalRoot.mcpServers === undefined ? [["mcpServers"]] : (prevGlobal?.created ?? []),
        );
        report.notes.push(`MCP server agent-vault written to ${global}`);
      }
      report.files.push(global);
      saveState(stateFile(), state);
      return report;
    },

    async uninstall(home) {
      const state = loadState(stateFile());
      const settings = settingsFile(home);
      const recordedSettings = state.files[settings];
      const settingsText = read(settings);
      if (settingsText !== null) {
        const root = parsed(settings, settingsText);
        const prefixes = prefixesOf(recordedSettings);
        let next = removeHooks(settingsText, isOurHook(prefixes), pruneFrom(recordedSettings));
        if (isOurHelper(root.apiKeyHelper, prefixes)) next = removeAt(next, ["apiKeyHelper"]);
        if (next !== settingsText) {
          backupFile(settings, backupsDir());
          finish(settings, next, recordedSettings);
        }
      }
      delete state.files[settings];

      const global = globalFile(home);
      const recordedGlobal = state.files[global];
      const globalText = read(global);
      if (globalText !== null && mcpOf(parsed(global, globalText))) {
        backupFile(global, backupsDir());
        await runClaude(["mcp", "remove", "--scope", "user", MCP_NAME]);
        // The command may be absent, or may have failed; whatever it left is removed here.
        const after = read(global);
        if (after !== null && mcpOf(parsed(global, after))) {
          finish(
            global,
            removeAt(after, ["mcpServers", MCP_NAME], pruneFrom(recordedGlobal)),
            recordedGlobal,
          );
        }
      }
      delete state.files[global];
      saveState(stateFile(), state);
    },

    async doctor(home): Promise<DoctorReport> {
      const checks: DoctorCheck[] = [];
      const add = (name: string, ok: boolean, detail: string, fix?: string): void => {
        checks.push({ name, ok, detail, ...(fix !== undefined && !ok && { fix }) });
      };
      const reinstall = "agent-vault install claude-code";

      const settings = settingsFile(home);
      let settingsText: string | null = null;
      let root: Record<string, unknown> = {};
      try {
        settingsText = read(settings);
        root = parsed(settings, settingsText);
      } catch (err) {
        add("settings", false, (err as Error).message);
      }

      // hooks
      const prefixes = prefixesOf(loadState(stateFile()).files[settings]);
      const found = settingsText === null ? [] : findHooks(settingsText, isOurHook(prefixes));
      const has = (event: string, event2: string): { event: string; command: string } | undefined =>
        found.find((h) => h.event === event && h.command.endsWith(` ${event2}`));
      const prompt = has("UserPromptSubmit", "prompt-submit");
      const missing = [
        prompt ? null : "UserPromptSubmit",
        has("SessionEnd", "scrub") ? null : "SessionEnd",
        has("SessionStart", "scrub") ? null : "SessionStart",
      ].filter((e): e is string => e !== null);
      if (missing.length > 0) {
        add(
          "hooks",
          false,
          `no agent-vault hook for ${missing.join(", ")} in ${settings}`,
          reinstall,
        );
      } else {
        const gone = found
          .flatMap((h) => splitCommand(h.command).filter((w) => path.isAbsolute(w)))
          .filter((w) => !fs.existsSync(w));
        if (gone.length > 0) {
          add("hooks", false, `the hook runs ${gone[0]}, which does not exist`, reinstall);
        } else {
          add("hooks", true, `3 hook entries in ${settings}`);
          const node = splitCommand(found[0]?.command ?? "")[0] ?? "";
          const manager = versionManagerOf(node);
          if (manager) {
            const last = checks[checks.length - 1] as DoctorCheck;
            last.warning = `the hooks run ${node}, which belongs to ${manager}: if that Node version is removed, prompt capture stops without any message`;
          }
        }
      }

      // settings that switch every hook off, ours included, without a word
      const switches: { file: string; key: string }[] = [];
      for (const file of [settings, path.join(configDir(home), "settings.local.json")]) {
        let fileRoot: Record<string, unknown>;
        try {
          fileRoot = file === settings ? root : parsed(file, read(file));
        } catch {
          continue; // settings.json is reported above; a broken local file is Claude's to report
        }
        for (const key of ["disableAllHooks", "allowManagedHooksOnly"]) {
          if (fileRoot[key] === true) switches.push({ file, key });
        }
      }
      const off = switches[0];
      if (off) {
        add(
          "hooks enabled",
          false,
          `${off.key} is true in ${off.file}, so Claude Code runs no agent-vault hook`,
          `remove ${off.key} from ${off.file}`,
        );
      } else {
        add(
          "hooks enabled",
          true,
          "neither disableAllHooks nor allowManagedHooksOnly is set in your settings (a managed policy can still turn hooks off; doctor does not read it)",
        );
      }

      // daemon and vault
      let client: HookClient | undefined;
      try {
        client = await deps.client();
        add("daemon", true, "reachable");
        const status = await client.call<{ initialized: boolean; locked: boolean }>("status");
        if (!status.initialized) add("vault", false, "not initialized", "agent-vault init");
        else if (status.locked) add("vault", false, "locked", "agent-vault recover");
        else add("vault", true, "initialized and unlocked");
      } catch (err) {
        if (!checks.some((c) => c.name === "daemon")) {
          add("daemon", false, (err as Error).message, "agent-vault daemon run");
        } else {
          add("vault", false, (err as Error).message, "agent-vault status");
        }
      } finally {
        client?.close();
      }

      // MCP
      let mcpOk = false;
      try {
        const globalText = read(globalFile(home));
        mcpOk = globalText !== null && mcpOf(parsed(globalFile(home), globalText)) !== undefined;
      } catch {
        // an unreadable file is reported as not registered
      }
      add(
        "mcp",
        mcpOk,
        mcpOk ? `agent-vault registered in ${globalFile(home)}` : "agent-vault is not registered",
        reinstall,
      );

      checks.push(
        wrappedServersCheck([globalFile(home)], "claude", { self: deps.command, env, platform }),
      );

      // probe: run the installed command line on a prompt that holds a made-up key
      if (!prompt) {
        add("probe", false, "no prompt-submit hook to run", reinstall);
      } else {
        const key = fakeKey();
        const stdin = JSON.stringify({
          session_id: "doctor-probe",
          transcript_path: "",
          cwd: process.cwd(),
          hook_event_name: "UserPromptSubmit",
          prompt: `agent-vault doctor probe ${key}`,
        });
        const run = await runProbe(`${prompt.command} --probe`, stdin);
        let blocked = false;
        try {
          blocked = (JSON.parse(run.stdout) as { decision?: unknown }).decision === "block";
        } catch {
          // not JSON: reported below
        }
        if (blocked) add("probe", true, "the installed hook blocked a made-up key");
        else {
          add(
            "probe",
            false,
            `the installed hook did not block a made-up key (exit ${run.code ?? "none"})`,
            reinstall,
          );
        }
      }

      // apiKeyHelper
      const helper = root.apiKeyHelper;
      if (helper === undefined) add("apiKeyHelper", true, "not set");
      else if (!isOurHelper(helper, prefixes))
        add("apiKeyHelper", true, "set to a helper that is not ours");
      else {
        const gone = splitCommand(String(helper)).filter(
          (w) => path.isAbsolute(w) && !fs.existsSync(w),
        );
        if (gone.length > 0) {
          add("apiKeyHelper", false, `it runs ${gone[0]}, which does not exist`, reinstall);
        } else add("apiKeyHelper", true, "ours, and its binary exists");
      }

      return { harness: "claude-code", ok: checks.every((c) => c.ok), checks };
    },

    async handleHook(event, input, opts?: HookOptions): Promise<HookOutput> {
      const harness = "claude-code";
      if (event === "scrub") {
        await handleScrub({ harness, client: deps.client, log });
        return null;
      }
      if (event !== "prompt-submit" || !isRecord(input) || typeof input.prompt !== "string") {
        return null;
      }
      const decision = await handlePromptSubmit({
        harness,
        prompt: input.prompt,
        transcriptPath: str(input.transcript_path),
        historyFiles: adapter.historyFiles(homeDir(), input),
        client: deps.client,
        probe: opts?.probe,
        deadlineMs: deps.deadlineMs,
        log,
      });
      return decision.block ? blockOutput(decision.reason) : null;
    },

    blockOutput,

    historyFiles(home, input) {
      const transcript = isRecord(input) ? str(input.transcript_path) : undefined;
      return [path.join(configDir(home), "history.jsonl"), ...(transcript ? [transcript] : [])];
    },
  };
  return adapter;
}
