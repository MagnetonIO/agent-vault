import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
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
import {
  defaultRunProbe,
  fakeKey,
  type ProbeRunner,
  tagFirst,
  versionManagerOf,
} from "./claude-code.js";
import { codexHomeDir } from "./config-dirs.js";
import { type HookClient, handlePromptSubmit, handleScrub } from "./hook.js";
import {
  appendHook,
  findHooks,
  type HookEntry,
  type HookSpec,
  quoteCommand,
  removeHookEntry,
  removeHooks,
  splitCommand,
} from "./hook-config.js";
import {
  type FileState,
  type InstallState,
  loadState,
  pruneFrom,
  saveState,
} from "./install-state.js";
import { JsonEditError, type JsonPath, missingContainers, parseJson } from "./json-edit.js";
import {
  appendTable,
  insertUnderHeader,
  parseToml,
  type TomlEdit,
  TomlEditError,
  tomlArray,
  tomlString,
  undoEdit,
} from "./toml-edit.js";
import { wrappedServersCheck } from "./wrapped-check.js";

/** Marks our entries in `hooks.json`: install keeps or replaces them and uninstall removes them. */
export const CODEX_HOOK_MARKER = " hook codex ";
/** Codex skips a hook it has not been told to trust, without a word, and sends the prompt on. */
export const TRUST_ACTION =
  "ACTION NEEDED: open Codex, run /hooks, select agent-vault and press t. Until then Codex skips the hook and pasted keys reach the model.";
const MCP_NAME = "agent-vault";
const DEFAULT_PROVIDER = "openai";
const PROMPT_TIMEOUT_S = 30;
const SCRUB_TIMEOUT_S = 15;
const CODEX_TIMEOUT_MS = 30_000;

/** Runs `codex <args>` (no shell). `code` is null if the binary is absent or could not start. */
export type CodexRunner = (args: string[]) => Promise<{ code: number | null }>;

export type CodexDeps = {
  /** How to run agent-vault, as absolute words: `[node, main.js]`, or the single-file binary. */
  command: string[];
  /** Connects to the daemon. */
  client: () => Promise<HookClient>;
  /** The user's home. Default `os.homedir()`. */
  home?: string | undefined;
  /** Default `process.env`; `CODEX_HOME` and (for `doctor`) PATH are read from it. */
  env?: NodeJS.ProcessEnv | undefined;
  /** What an install records for its uninstall. Default `<dataDir>/adapters/codex-state.json`. */
  stateFile?: string | undefined;
  /** Overall deadline of the prompt hook; see `HOOK_DEADLINE_MS`. */
  deadlineMs?: number | undefined;
  /** Default `getPaths().backupsDir`. */
  backupsDir?: string | undefined;
  /** Default: spawn `codex` from PATH. Tests inject one: they must never run the real binary. */
  runCodex?: CodexRunner | undefined;
  /** Default: spawn the command in a shell. */
  runProbe?: ProbeRunner | undefined;
  platform?: NodeJS.Platform | undefined;
  /** For stderr. */
  log?: ((message: string) => void) | undefined;
};

/** What install did to `config.toml`, so uninstall can take back exactly that. */
type ConfigRecord = {
  createdFile: boolean;
  /** "cli" if `codex mcp add` wrote the MCP table (uninstall runs `codex mcp remove`). */
  mcp: "cli" | null;
  edits: TomlEdit[];
  /** Trust keys whose hook changed under them, with the `trusted_hash` that went stale. */
  staleTrust: Record<string, string>;
  /** Where our hooks sat when last installed (`user_prompt_submit` to `0:0`). */
  slots: Record<string, string>;
};

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const str = (v: unknown): string | undefined => (typeof v === "string" && v ? v : undefined);

/** `UserPromptSubmit` as Codex spells it in a trust key. */
const snake = (event: string): string => event.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase();

function defaultRunCodex(env: NodeJS.ProcessEnv): CodexRunner {
  return (args) =>
    new Promise((resolve) => {
      const child = spawn("codex", args, {
        stdio: "ignore",
        env,
        windowsHide: true,
        timeout: CODEX_TIMEOUT_MS,
      });
      child.once("error", () => resolve({ code: null }));
      child.once("close", (code) => resolve({ code }));
    });
}

const recordIsEmpty = (r: ConfigRecord): boolean =>
  !r.createdFile &&
  r.mcp === null &&
  r.edits.length === 0 &&
  Object.keys(r.staleTrust).length === 0 &&
  Object.keys(r.slots).length === 0;

/** `value` with every table a plain object (the TOML parser makes them without a prototype). */
function plain(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(plain);
  if (isRecord(value))
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, plain(v)]));
  return value;
}

/** `value` with `path` set to `to`, on a copy. */
function withPath(value: Record<string, unknown>, keys: string[], to: unknown): unknown {
  const copy = plain(value) as Record<string, unknown>;
  let node = copy;
  keys.forEach((k, i) => {
    if (i === keys.length - 1) node[k] = to;
    else {
      if (!isRecord(node[k])) node[k] = {};
      node = node[k] as Record<string, unknown>;
    }
  });
  return copy;
}

export function createCodexAdapter(deps: CodexDeps): HarnessAdapter {
  const env = deps.env ?? process.env;
  const platform = deps.platform ?? process.platform;
  const log = deps.log ?? (() => {});
  const runProbe = deps.runProbe ?? defaultRunProbe(env);
  const homeDir = (): string => deps.home ?? os.homedir();
  const backupsDir = (): string => deps.backupsDir ?? getPaths().backupsDir;
  const stateFile = (): string =>
    deps.stateFile ?? path.join(getPaths().dataDir, "adapters", "codex-state.json");

  const codexHome = (home: string): string => codexHomeDir(home, env.CODEX_HOME);
  const hooksFile = (home: string): string => path.join(codexHome(home), "hooks.json");
  const configFile = (home: string): string => path.join(codexHome(home), "config.toml");
  const runCodex = (home: string): CodexRunner =>
    deps.runCodex ?? defaultRunCodex({ ...env, CODEX_HOME: codexHome(home) });

  const words = (...extra: string[]): string => quoteCommand([...deps.command, ...extra], platform);
  const hookSpecs = (): HookSpec[] => [
    {
      event: "UserPromptSubmit",
      command: words("hook", "codex", "prompt-submit"),
      timeout: PROMPT_TIMEOUT_S,
    },
    // S3 never saw SessionEnd in Codex: the scrub runs at the next SessionStart.
    { event: "SessionStart", command: words("hook", "codex", "scrub"), timeout: SCRUB_TIMEOUT_S },
  ];

  /** The command words this adapter writes now, quoted. */
  const prefix = (): string => quoteCommand(deps.command, platform);
  /**
   * Entries are ours only if they start with the command words an install wrote: the ones it
   * would write now, or the ones it recorded (the binary may have moved since).
   */
  const prefixesOf = (recorded: FileState | undefined): string[] => [
    ...new Set([prefix(), ...(recorded ? [recorded.prefix] : [])]),
  ];
  const isOurHook =
    (prefixes: string[]) =>
    (command: string): boolean =>
      prefixes.some((p) => command.startsWith(`${p}${CODEX_HOOK_MARKER}`));

  const read = (file: string): string | null => {
    try {
      return fs.readFileSync(file, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  };

  const parsedJson = (file: string, text: string | null): Record<string, unknown> => {
    try {
      return text === null ? {} : parseJson(text);
    } catch (err) {
      const why = err instanceof JsonEditError ? err.message : String(err);
      throw new AdapterError(`${file} is not usable (${why}); fix it by hand first`);
    }
  };
  const parsedToml = (file: string, text: string | null): Record<string, unknown> => {
    try {
      return text === null ? {} : parseToml(text);
    } catch (err) {
      const why = err instanceof TomlEditError ? err.message : String(err);
      throw new AdapterError(`${file} is not usable (${why}); fix it by hand first`);
    }
  };

  /** The config.toml part of the state (kept in the `toml` field of its `FileState`). */
  const recordOf = (state: InstallState, configPath: string): ConfigRecord => {
    const f = state.files[configPath];
    return {
      createdFile: f?.createdFile ?? false,
      mcp: f?.toml?.mcp ?? null,
      edits: f?.toml?.edits ?? [],
      staleTrust: f?.toml?.staleTrust ?? {},
      slots: f?.toml?.slots ?? {},
    };
  };
  const storeRecord = (state: InstallState, configPath: string, rec: ConfigRecord): void => {
    if (recordIsEmpty(rec)) delete state.files[configPath];
    else {
      state.files[configPath] = {
        createdFile: rec.createdFile,
        created: [],
        prefix: prefix(),
        toml: { mcp: rec.mcp, edits: rec.edits, staleTrust: rec.staleTrust, slots: rec.slots },
      };
    }
  };

  const put = (file: string, text: string, existed: boolean): void => {
    if (existed) writeFileAtomic(file, text);
    else {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, text, { mode: 0o600 });
    }
  };

  /** The paths a trust key for `file` may use: Codex may have resolved a symlink or a drive. */
  const fileKeys = (file: string): string[] => {
    const keys = new Set([file, file.replaceAll("\\", "/")]);
    try {
      keys.add(fs.realpathSync(file));
    } catch {
      // the file is not there
    }
    return [...keys];
  };
  const trustTable = (root: Record<string, unknown>): Record<string, unknown> => {
    const hooks = root.hooks;
    return isRecord(hooks) && isRecord(hooks.state) ? hooks.state : {};
  };
  /** The `trusted_hash` Codex recorded for this hook, with its key, if there is one. */
  const trustOf = (
    root: Record<string, unknown>,
    file: string,
    entry: Pick<HookEntry, "event" | "group" | "index">,
  ): { key: string; hash: string } | undefined => {
    const table = trustTable(root);
    for (const prefix of fileKeys(file)) {
      const key = `${prefix}:${snake(entry.event)}:${entry.group}:${entry.index}`;
      const row = table[key];
      if (isRecord(row) && typeof row.trusted_hash === "string" && row.trusted_hash) {
        return { key, hash: row.trusted_hash };
      }
    }
    return undefined;
  };

  const mcpOf = (root: Record<string, unknown>): Record<string, unknown> | undefined => {
    const entry = isRecord(root.mcp_servers) ? root.mcp_servers[MCP_NAME] : undefined;
    return isRecord(entry) ? entry : undefined;
  };
  const sameMcp = (entry: Record<string, unknown>): boolean =>
    entry.command === deps.command[0] &&
    Array.isArray(entry.args) &&
    isDeepStrictEqual(plain(entry.args), [...deps.command.slice(1), "mcp"]);

  /**
   * `edit` applied to `text`, after checking that the result parses and differs from the parse of
   * `text` only by `value` at `keys`. A file layout the splice cannot honour (an inline table, a
   * dotted key) fails here, not in Codex.
   */
  const checked = (
    file: string,
    text: string,
    made: { text: string; edit: TomlEdit },
    keys: string[],
    value: unknown,
  ): { text: string; edit: TomlEdit } => {
    let ok = false;
    try {
      ok = isDeepStrictEqual(plain(parseToml(made.text)), withPath(parseToml(text), keys, value));
    } catch {
      // reported below
    }
    if (!ok) {
      throw new AdapterError(
        `${file} defines ${keys.join(".")} in a form that cannot be edited safely; set it by hand`,
      );
    }
    return made;
  };

  /** The `[mcp_servers.agent-vault]` table `codex mcp add` would write, and what it parses to. */
  const mcpTable = (): { lines: string[]; value: unknown } => {
    const args = [...deps.command.slice(1), "mcp"];
    return {
      lines: [
        `[mcp_servers.${MCP_NAME}]`,
        `command = ${tomlString(deps.command[0] as string)}`,
        `args = ${tomlArray(args)}`,
      ],
      value: { command: deps.command[0], args },
    };
  };

  function blockOutput(reason: string): HookOutput {
    return { decision: "block", reason };
  }

  const adapter: HarnessAdapter = {
    id: "codex",

    async detect(home) {
      return fs.existsSync(codexHome(home));
    },

    async install({ home, modelKey, provider, noHistory }: InstallOptions): Promise<InstallReport> {
      // Everything that can refuse comes before the first write.
      if (!path.isAbsolute(deps.command[0] ?? "")) {
        throw new AdapterError(
          "cannot tell where agent-vault is installed: run the built CLI (pnpm build) or the single-file binary",
        );
      }
      if (provider !== undefined && modelKey === undefined) {
        throw new AdapterError("--provider only applies together with --model-key");
      }
      const providerId = provider ?? DEFAULT_PROVIDER;
      if (!/^[A-Za-z0-9_-]+$/.test(providerId)) {
        throw new AdapterError(
          `model provider id "${providerId}" may only use letters, digits, _ and -`,
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

      const hooksPath = hooksFile(home);
      const configPath = configFile(home);
      const hooksText = read(hooksPath);
      const hooksRoot = parsedJson(hooksPath, hooksText);
      if (!isRecord(hooksRoot.hooks ?? {})) {
        throw new AdapterError(`${hooksPath}: "hooks" is not an object; fix it by hand first`);
      }
      const configText = read(configPath);
      const configRoot = parsedToml(configPath, configText);
      const providerEntry = isRecord(configRoot.model_providers)
        ? configRoot.model_providers[providerId]
        : undefined;
      const wantAuth =
        modelKey === undefined
          ? undefined
          : {
              command: deps.command[0] as string,
              args: [...deps.command.slice(1), "helper", modelKey],
            };
      // The same auth as an earlier install of ours wrote (or the user wrote) is not a conflict.
      const authIsOurs =
        isRecord(providerEntry) &&
        wantAuth !== undefined &&
        isDeepStrictEqual(plain(providerEntry.auth), wantAuth);
      if (
        modelKey !== undefined &&
        isRecord(providerEntry) &&
        providerEntry.auth !== undefined &&
        !authIsOurs
      ) {
        throw new AdapterError(
          `${configPath} already sets auth for model provider "${providerId}"; remove it first, then retry`,
        );
      }
      const history = isRecord(configRoot.history) ? configRoot.history : undefined;
      if (noHistory && history?.persistence !== undefined && history.persistence !== "none") {
        throw new AdapterError(
          `${configPath} already sets history.persistence to ${JSON.stringify(history.persistence)}; change it to "none" by hand`,
        );
      }

      // Plan the config.toml edits in memory; they fail here, before any file changes.
      let cfg = configText ?? "";
      const edits: TomlEdit[] = [];
      const modelNotes: string[] = [];
      if (noHistory && history?.persistence !== "none") {
        const line = 'persistence = "none"';
        const made =
          (history ? insertUnderHeader(cfg, ["history"], line) : null) ??
          appendTable(cfg, ["[history]", line]);
        cfg = checked(configPath, cfg, made, ["history", "persistence"], "none").text;
        edits.push(made.edit);
        modelNotes.push(
          'history: [history] persistence = "none" set. This disables ALL Codex history, not only blocked prompts',
        );
      }
      if (modelKey !== undefined && authIsOurs) {
        modelNotes.push(`model key: ${providerId} already gets its key from ${modelKey}`);
      } else if (modelKey !== undefined) {
        const auth = wantAuth as { command: string; args: string[] };
        const made = appendTable(cfg, [
          `[model_providers.${providerId}.auth]`,
          `command = ${tomlString(auth.command)}`,
          `args = ${tomlArray(auth.args)}`,
        ]);
        cfg = checked(configPath, cfg, made, ["model_providers", providerId, "auth"], auth).text;
        edits.push(made.edit);
        modelNotes.push(`model key: ${providerId} gets its key from ${modelKey} in the vault`);
      }

      // The MCP table is appended later if `codex mcp add` does not work: make sure it could be.
      if (!mcpOf(configRoot)) {
        const lines = mcpTable();
        checked(
          configPath,
          cfg,
          appendTable(cfg, lines.lines),
          ["mcp_servers", MCP_NAME],
          lines.value,
        );
      }

      // hooks.json: keep what is already right (trust is tied to a hook's command and place).
      const state = loadState(stateFile());
      const prevHooks = state.files[hooksPath];
      const prefixes = prefixesOf(prevHooks);
      const isOurs = isOurHook(prefixes);
      const specs = hookSpecs();
      const oldHooks = hooksText ?? "";
      let nextHooks = oldHooks;
      const wanted = new Set(specs.map((s) => `${s.event}\0${s.command}`));
      const kept = new Set<string>();
      const stale = findHooks(nextHooks, isOurs).filter((h) => {
        const k = `${h.event}\0${h.command}`;
        if (!wanted.has(k) || kept.has(k)) return true;
        kept.add(k);
        return false;
      });
      for (const h of stale.reverse()) nextHooks = removeHookEntry(nextHooks, h);
      const created: JsonPath[] = [];
      for (const spec of specs) {
        if (kept.has(`${spec.event}\0${spec.command}`)) continue;
        for (const p of missingContainers(nextHooks, ["hooks", spec.event])) {
          if (!created.some((c) => c.join("\0") === p.join("\0"))) created.push(p);
        }
        nextHooks = appendHook(nextHooks, spec);
      }
      // Containers a previous install made and the user has since filled stay recorded.
      for (const p of prevHooks?.created ?? []) {
        if (
          missingContainers(nextHooks, p).length === 0 &&
          !created.some((c) => c.join("\0") === p.join("\0"))
        ) {
          created.push(p);
        }
      }
      const hooksChanged = nextHooks !== oldHooks;

      const report: InstallReport = {
        harness: "codex",
        files: [],
        backups: [],
        notes: [],
        warnings: [],
      };
      const manager = versionManagerOf(deps.command[0] as string);
      if (manager) {
        report.warnings?.push(
          `the hooks run ${deps.command[0]}, which belongs to ${manager}: removing or switching that Node version silently disables prompt capture. Run \`agent-vault doctor codex\` after upgrading Node, or install the single-file binary.`,
        );
      }
      const rec = recordOf(state, configPath);
      const persist = (): void => {
        storeRecord(state, configPath, rec);
        saveState(stateFile(), state);
      };
      const backedUp = new Set<string>();
      const backup = (file: string): void => {
        if (backedUp.has(file) || !fs.existsSync(file)) return;
        backedUp.add(file);
        report.backups.push(backupFile(file, backupsDir()));
      };

      // Codex keys trust by position. If our hook sits elsewhere than when last installed, a trust
      // entry at its new place belongs to whatever hook was there: it must not count for ours.
      for (const h of findHooks(nextHooks, isOurs)) {
        const slot = `${h.group}:${h.index}`;
        const before = rec.slots[snake(h.event)];
        const there =
          before !== undefined && before !== slot ? trustOf(configRoot, hooksPath, h) : undefined;
        if (there) rec.staleTrust[there.key] = there.hash;
        rec.slots[snake(h.event)] = slot;
      }

      if (hooksChanged) {
        // Trust entries Codex wrote for hooks that are no longer what they were stay in config.toml.
        const before = new Map(
          findHooks(oldHooks, "").map((h) => [
            `${snake(h.event)}:${h.group}:${h.index}`,
            h.command,
          ]),
        );
        const after = new Map(
          findHooks(nextHooks, "").map((h) => [
            `${snake(h.event)}:${h.group}:${h.index}`,
            h.command,
          ]),
        );
        for (const [key, row] of Object.entries(trustTable(configRoot))) {
          const prefix = fileKeys(hooksPath).find((p) => key.startsWith(`${p}:`));
          if (prefix === undefined || !isRecord(row)) continue;
          const slot = key.slice(prefix.length + 1);
          if (typeof row.trusted_hash === "string" && before.get(slot) !== after.get(slot)) {
            rec.staleTrust[key] = row.trusted_hash;
          }
        }
        const whitespace =
          hooksText !== null && hooksText.trim() === "" ? hooksText : prevHooks?.whitespace;
        state.files[hooksPath] = {
          createdFile: hooksText === null || (prevHooks?.createdFile ?? false),
          ...(whitespace !== undefined && { whitespace }),
          created,
          prefix: prefix(),
        };
        persist();
        backup(hooksPath);
        put(hooksPath, nextHooks, hooksText !== null);
        report.files.push(hooksPath);
      }

      if (edits.length > 0) {
        const mark = rec.edits.length;
        rec.edits.push(...edits);
        if (configText === null) rec.createdFile = true;
        persist();
        try {
          backup(configPath);
          put(configPath, cfg, configText !== null);
        } catch (err) {
          rec.edits.length = mark;
          if (configText === null) rec.createdFile = false;
          persist();
          throw err;
        }
        report.files.push(configPath);
      }
      report.notes.push(
        hooksChanged
          ? `hooks: UserPromptSubmit, SessionStart in ${hooksPath}`
          : `hooks: already in place in ${hooksPath}, left as they were`,
      );
      report.notes.push(...modelNotes);

      // MCP: the CLI first, then the table it would have written.
      const current = parsedToml(configPath, read(configPath));
      const existing = mcpOf(current);
      if (existing && sameMcp(existing)) {
        report.notes.push("MCP server agent-vault was already registered");
      } else if (existing) {
        report.notes.push(
          `MCP server agent-vault is registered with a different command; to repoint it run: codex mcp remove agent-vault, then agent-vault install codex`,
        );
      } else {
        backup(configPath);
        const run = await runCodex(home)(["mcp", "add", MCP_NAME, "--", ...deps.command, "mcp"]);
        let viaCli = false;
        if (run.code === 0) {
          try {
            viaCli = mcpOf(parsedToml(configPath, read(configPath))) !== undefined;
          } catch {
            // a config the CLI left unreadable is rewritten below
          }
        }
        if (viaCli) {
          rec.mcp = "cli";
          if (configText === null) rec.createdFile = true;
          if (!report.files.includes(configPath)) report.files.push(configPath);
          report.notes.push("MCP server agent-vault added with `codex mcp add`");
        } else {
          // No `codex` on PATH, or it failed: write the table it would have written.
          const text = read(configPath);
          const table = mcpTable();
          const made = checked(
            configPath,
            text ?? "",
            appendTable(text ?? "", table.lines),
            ["mcp_servers", MCP_NAME],
            table.value,
          );
          rec.edits.push(made.edit);
          if (text === null) rec.createdFile = true;
          persist();
          put(configPath, made.text, text !== null);
          if (!report.files.includes(configPath)) report.files.push(configPath);
          report.notes.push(`MCP server agent-vault written to ${configPath}`);
        }
      }

      persist();

      // Trust: only Codex can grant it. If the hook is unchanged and already trusted, nothing to ask.
      const prompt = findHooks(nextHooks, isOurs).find((h) => h.event === "UserPromptSubmit");
      const trusted = prompt
        ? trustOf(parsedToml(configPath, read(configPath)), hooksPath, prompt)
        : undefined;
      const stillTrusted = trusted !== undefined && rec.staleTrust[trusted.key] !== trusted.hash;
      if (!hooksChanged && stillTrusted) {
        report.notes.push("the prompt hook is already trusted by Codex; nothing more to do");
      } else {
        report.action = TRUST_ACTION;
      }
      return report;
    },

    async uninstall(home) {
      const hooksPath = hooksFile(home);
      const configPath = configFile(home);
      const state = loadState(stateFile());
      const recordedHooks = state.files[hooksPath];
      const rec = recordOf(state, configPath);

      const hooksText = read(hooksPath);
      if (hooksText !== null) {
        parsedJson(hooksPath, hooksText);
        const ours = isOurHook(prefixesOf(recordedHooks));
        const next = removeHooks(hooksText, ours, pruneFrom(recordedHooks));
        // Removing our group moves every later group of that event up by one.
        const placeOf = (text: string): Map<string, string> =>
          new Map(
            findHooks(text, (c) => !ours(c)).map((h) => [
              `${h.event}\0${h.command}`,
              `${h.group}:${h.index}`,
            ]),
          );
        const placed = placeOf(next);
        const moved = [...placeOf(hooksText)].some(([k, v]) => placed.get(k) !== v);
        if (moved) {
          log(
            "your hooks after agent-vault's moved position; Codex may now treat them as untrusted; re-run /hooks",
          );
        }
        if (next !== hooksText) {
          backupFile(hooksPath, backupsDir());
          const bare = Object.keys(parseJson(next)).length === 0;
          if (bare && recordedHooks?.createdFile) fs.rmSync(hooksPath, { force: true });
          else if (bare && recordedHooks?.whitespace !== undefined) {
            writeFileAtomic(hooksPath, recordedHooks.whitespace);
          } else writeFileAtomic(hooksPath, next);
        }
      }
      delete state.files[hooksPath];

      if (!recordIsEmpty(rec)) {
        if (rec.mcp === "cli" && fs.existsSync(configPath)) {
          backupFile(configPath, backupsDir());
          await runCodex(home)(["mcp", "remove", MCP_NAME]);
        }
        const text = read(configPath);
        if (text !== null) {
          let next = text;
          for (const edit of [...rec.edits].reverse()) {
            const undone = undoEdit(next, edit);
            if (undone === null) {
              const line = edit.text.trim().split(/\r?\n/)[0];
              log(`left ${line} in ${configPath} (it moved or was changed); remove it by hand`);
            } else next = undone;
          }
          if (rec.createdFile && next.trim() === "") {
            if (text !== "") backupFile(configPath, backupsDir());
            fs.rmSync(configPath);
          } else if (next !== text) {
            backupFile(configPath, backupsDir());
            writeFileAtomic(configPath, next);
          }
        }
      }
      delete state.files[configPath];
      saveState(stateFile(), state);
    },

    async doctor(home): Promise<DoctorReport> {
      const checks: DoctorCheck[] = [];
      const add = (
        name: string,
        ok: boolean,
        detail: string,
        fix?: string,
        severity?: "warn" | "info",
      ): void => {
        checks.push({
          name,
          ok,
          detail,
          ...(fix !== undefined && (!ok || severity === "warn") && { fix }),
          ...(severity !== undefined && { severity }),
        });
      };
      const reinstall = "agent-vault install codex";
      const hooksPath = hooksFile(home);
      const configPath = configFile(home);

      let hooksText: string | null = null;
      try {
        hooksText = read(hooksPath);
        parsedJson(hooksPath, hooksText);
      } catch (err) {
        hooksText = null;
        add("hooks", false, (err as Error).message, reinstall);
      }
      let root: Record<string, unknown> = {};
      try {
        root = parsedToml(configPath, read(configPath));
      } catch (err) {
        add("config", false, (err as Error).message);
      }

      // hooks
      const loaded = loadState(stateFile());
      const found =
        hooksText === null
          ? []
          : findHooks(hooksText, isOurHook(prefixesOf(loaded.files[hooksPath])));
      const prompt = found.find(
        (h) => h.event === "UserPromptSubmit" && h.command.endsWith(" prompt-submit"),
      );
      const scrub = found.find((h) => h.event === "SessionStart" && h.command.endsWith(" scrub"));
      if (!checks.some((c) => c.name === "hooks")) {
        const missing = [prompt ? null : "UserPromptSubmit", scrub ? null : "SessionStart"].filter(
          (e): e is string => e !== null,
        );
        if (missing.length > 0) {
          add(
            "hooks",
            false,
            `no agent-vault hook for ${missing.join(", ")} in ${hooksPath}`,
            reinstall,
          );
        } else {
          const gone = found
            .flatMap((h) => splitCommand(h.command).filter((w) => path.isAbsolute(w)))
            .filter((w) => !fs.existsSync(w));
          if (gone.length > 0) {
            add("hooks", false, `the hook runs ${gone[0]}, which does not exist`, reinstall);
          } else {
            add("hooks", true, `2 hook entries in ${hooksPath}`);
            const node = splitCommand(found[0]?.command ?? "")[0] ?? "";
            const manager = versionManagerOf(node);
            if (manager) {
              const last = checks[checks.length - 1] as DoctorCheck;
              last.warning = `the hooks run ${node}, which belongs to ${manager}: if that Node version is removed, prompt capture stops without any message`;
            }
          }
        }
      }

      // trust: Codex skips a hook it has not been told to trust, silently, and sends the prompt
      const stale = loaded.files[configPath]?.toml?.staleTrust ?? {};
      const trustFor = (h: HookEntry | undefined) => {
        const t = h ? trustOf(root, hooksPath, h) : undefined;
        return t && stale[t.key] !== t.hash ? t : undefined;
      };
      const proof = "presence only; run a real Codex prompt with a fake key to prove it fires";
      const note =
        "editing the hook command un-trusts it, so re-check after install or after a Codex upgrade";
      const was = loaded.files[configPath]?.toml?.slots?.user_prompt_submit;
      const now = prompt ? `${prompt.group}:${prompt.index}` : undefined;
      if (!prompt) {
        add("trust", false, "no prompt-submit hook to trust", reinstall);
      } else if (was !== undefined && was !== now) {
        add(
          "trust",
          false,
          `our hook moved from ${was} to ${now}; Codex keys trust by position; re-run /hooks and trust it`,
          "agent-vault install codex, then run /hooks in Codex and press t",
        );
      } else if (!trustFor(prompt)) {
        add(
          "trust",
          false,
          `hook not trusted: Codex will skip it and send pasted keys to the model (${proof}; ${note})`,
          "run /hooks in Codex and press t",
        );
      } else if (scrub && !trustFor(scrub)) {
        add(
          "trust",
          true,
          "the prompt hook is trusted, but the SessionStart scrub hook is not: Codex skips it until you press t on it in /hooks",
          "run /hooks in Codex and press t",
          "warn",
        );
      } else {
        add("trust", true, `trusted by Codex (${proof}; ${note})`);
      }

      // features: a Codex with hooks off ignores hooks.json altogether
      const features = isRecord(root.features) ? root.features : {};
      const off = ["hooks", "codex_hooks"].find((k) => features[k] === false);
      if (off) {
        add(
          "features",
          false,
          `features.${off} = false in ${configPath}: Codex ignores every hook, so pasted keys reach the model`,
          `remove features.${off} = false from ${configPath} (hooks are on by default)`,
        );
      } else add("features", true, "hooks are on (the default)");

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
      const mcp = mcpOf(root);
      if (!mcp) add("mcp", false, "agent-vault is not registered", reinstall);
      else if (!sameMcp(mcp)) {
        add(
          "mcp",
          false,
          `[mcp_servers.agent-vault] in ${configPath} runs a different command than this agent-vault (${String(mcp.command)})`,
          "codex mcp remove agent-vault, then agent-vault install codex",
        );
      } else add("mcp", true, `agent-vault registered in ${configPath}`);

      // probe: run the installed command line on a prompt that holds a made-up key
      if (!prompt) {
        add("probe", false, "no prompt-submit hook to run", reinstall);
      } else {
        const stdin = JSON.stringify({
          session_id: "doctor-probe",
          turn_id: "doctor-probe",
          transcript_path: "",
          cwd: process.cwd(),
          hook_event_name: "UserPromptSubmit",
          model: "doctor-probe",
          permission_mode: "default",
          prompt: `agent-vault doctor probe ${fakeKey()}`,
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

      checks.push(
        wrappedServersCheck([configPath], "codex", { self: deps.command, env, platform }),
      );

      // history
      const persistence = isRecord(root.history) ? root.history.persistence : undefined;
      if (persistence === "none") add("history", true, 'history.persistence = "none"');
      else {
        add(
          "history",
          true,
          "blocked prompts typed in the TUI land in history.jsonl until the next scrub",
          "agent-vault install codex --no-history (this turns off all Codex history)",
          "warn",
        );
      }

      const rel = path.relative(path.resolve(home), codexHome(home));
      if (rel.startsWith("..") || path.isAbsolute(rel)) {
        add(
          "scope",
          true,
          `CODEX_HOME (${codexHome(home)}) is outside your home directory: the daemon scrubs only files under it, so history and rollouts there are not scrubbed`,
          undefined,
          "info",
        );
      }
      const modelAuth = isRecord(root.model_providers)
        ? root.model_providers[DEFAULT_PROVIDER]
        : undefined;
      if (isRecord(modelAuth) && modelAuth.auth !== undefined) {
        add(
          "provider",
          true,
          `${DEFAULT_PROVIDER} is Codex's built-in provider: whether Codex honours a user auth table for it is untested`,
          undefined,
          "info",
        );
      }

      add(
        "sqlite",
        true,
        "state_5.sqlite and thread_history_1.sqlite are not scrubbed: a key that got past the hook can stay in them",
        undefined,
        "info",
      );

      return { harness: "codex", ok: checks.every((c) => c.ok), checks };
    },

    blockOutput,

    async handleHook(event, input, opts?: HookOptions): Promise<HookOutput> {
      const harness = "codex";
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

    historyFiles(home, input) {
      const transcript = isRecord(input) ? str(input.transcript_path) : undefined;
      return [path.join(codexHome(home), "history.jsonl"), ...(transcript ? [transcript] : [])];
    },
  };
  return adapter;
}
