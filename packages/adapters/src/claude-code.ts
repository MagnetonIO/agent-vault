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
import { type HookClient, handlePromptSubmit, handleScrub } from "./hook.js";
import {
  addHooks,
  findHooks,
  type HookSpec,
  quoteCommand,
  removeHooks,
  splitCommand,
} from "./hook-config.js";
import { JsonEditError, parseJson, removeAt, setAt } from "./json-edit.js";

/** Marks our entries in `settings.json`: install replaces them and uninstall removes them. */
export const CLAUDE_HOOK_MARKER = " hook claude-code ";
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
  /** Default `process.env`; only `CLAUDE_CONFIG_DIR` is read from it. */
  env?: NodeJS.ProcessEnv | undefined;
  /** Default `getPaths().backupsDir`. */
  backupsDir?: string | undefined;
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

  const configDir = (home: string): string =>
    env.CLAUDE_CONFIG_DIR ? path.resolve(env.CLAUDE_CONFIG_DIR) : path.join(home, ".claude");
  const settingsFile = (home: string): string => path.join(configDir(home), "settings.json");
  /** Claude keeps its user-scope config (MCP servers) beside the config dir, or inside it. */
  const globalFile = (home: string): string =>
    env.CLAUDE_CONFIG_DIR
      ? path.join(configDir(home), ".claude.json")
      : path.join(home, ".claude.json");

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
  /** What `apiKeyHelper` looks like when agent-vault wrote it, wherever the binary was then. */
  const isOurHelper = (value: unknown): boolean =>
    typeof value === "string" &&
    (value.startsWith(`${quoteCommand(deps.command, platform)} helper `) ||
      /(?:agent-vault(?:\.exe)?|main\.js)['"]? helper [a-z0-9][a-z0-9._/-]*$/.test(value));
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
      if (
        modelKey !== undefined &&
        settingsRoot.apiKeyHelper !== undefined &&
        !isOurHelper(settingsRoot.apiKeyHelper)
      ) {
        throw new AdapterError(
          `${settings} already sets apiKeyHelper to something else; remove it first, then retry`,
        );
      }

      const report: InstallReport = { harness: "claude-code", files: [], backups: [], notes: [] };

      let next = addHooks(settingsText ?? "", hookSpecs(), CLAUDE_HOOK_MARKER);
      if (modelKey !== undefined) next = setAt(next, ["apiKeyHelper"], helperCommand(modelKey));
      write(settings, next, report.backups, settingsText !== null);
      report.files.push(settings);
      report.notes.push("hooks: UserPromptSubmit, SessionEnd, SessionStart");
      if (modelKey !== undefined)
        report.notes.push(`apiKeyHelper reads ${modelKey} from the vault`);

      const existing = mcpOf(globalRoot);
      if (existing && sameMcp(existing)) {
        report.notes.push("MCP server agent-vault was already registered");
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
        report.notes.push("MCP server agent-vault added with `claude mcp add --scope user`");
      } else {
        // No `claude` on PATH, or it failed: write the entry it would have written.
        const text = setAt(globalText ?? "", ["mcpServers", MCP_NAME], mcpEntry());
        if (globalText !== null) writeFileAtomic(global, text);
        else write(global, text, report.backups, false);
        report.notes.push(`MCP server agent-vault written to ${global}`);
      }
      report.files.push(global);
      return report;
    },

    async uninstall(home) {
      const settings = settingsFile(home);
      const settingsText = read(settings);
      if (settingsText !== null) {
        const root = parsed(settings, settingsText);
        let next = removeHooks(settingsText, CLAUDE_HOOK_MARKER);
        if (isOurHelper(root.apiKeyHelper)) next = removeAt(next, ["apiKeyHelper"]);
        if (next !== settingsText) {
          backupFile(settings, backupsDir());
          writeFileAtomic(settings, next);
        }
      }

      const global = globalFile(home);
      const globalText = read(global);
      if (globalText !== null && mcpOf(parsed(global, globalText))) {
        backupFile(global, backupsDir());
        await runClaude(["mcp", "remove", "--scope", "user", MCP_NAME]);
        // The command may be absent, or may have failed; whatever it left is removed here.
        const after = read(global);
        if (after !== null && mcpOf(parsed(global, after))) {
          writeFileAtomic(global, removeAt(after, ["mcpServers", MCP_NAME]));
        }
      }
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
      const found = settingsText === null ? [] : findHooks(settingsText, CLAUDE_HOOK_MARKER);
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
        }
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
      else if (!isOurHelper(helper)) add("apiKeyHelper", true, "set to a helper that is not ours");
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
        log,
      });
      return decision.block ? blockOutput(decision.reason) : null;
    },

    historyFiles(home, input) {
      const transcript = isRecord(input) ? str(input.transcript_path) : undefined;
      return [path.join(configDir(home), "history.jsonl"), ...(transcript ? [transcript] : [])];
    },
  };
  return adapter;
}
