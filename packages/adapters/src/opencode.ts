import fs from "node:fs";
import path from "node:path";
import { getPaths } from "@agent-vault/platform";
import {
  AdapterError,
  type DoctorCheck,
  type DoctorReport,
  type HarnessAdapter,
  type HookOutput,
  type InstallOptions,
  type InstallReport,
} from "./adapter.js";
import { backupFile, writeFileAtomic } from "./backup.js";
import type { HookClient } from "./hook.js";
import { JsonEditError, parseJson, removeAt, setAt } from "./json-edit.js";

/** What a new `opencode.json` starts with. */
export const OPENCODE_SCHEMA = "https://opencode.ai/config.json";
const MCP_NAME = "agent-vault";

/** Shown by `doctor`. Prompt capture waits for a documented OpenCode hook (spike S3, decision 4). */
const PROMPT_CAPTURE = "use agent-vault grab (no OpenCode prompt hook yet)";
const DB_NOTE =
  "pasted text is stored in opencode.db, which agent-vault does not scrub; run agent-vault scan to find exposed keys";

export type OpenCodeDeps = {
  /** How to run agent-vault, as absolute words: `[node, main.js]`, or the single-file binary. */
  command: string[];
  /** Connects to the daemon. */
  client: () => Promise<HookClient>;
  /** For one-line notices on stderr (uninstall leaving an entry alone). */
  log?: ((message: string) => void) | undefined;
  /** Default `process.env`; only `XDG_CONFIG_HOME` is read from it. */
  env?: NodeJS.ProcessEnv | undefined;
  /** Default `getPaths().backupsDir`. */
  backupsDir?: string | undefined;
};

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

/**
 * The OpenCode adapter. It only edits `opencode.json` (or `.jsonc`): the `opencode` binary is
 * never run, because a command without `--standalone` attaches to the user's shared background
 * service (spike S3).
 */
export function createOpenCodeAdapter(deps: OpenCodeDeps): HarnessAdapter {
  const env = deps.env ?? process.env;
  const log = deps.log ?? (() => {});
  const backupsDir = (): string => deps.backupsDir ?? getPaths().backupsDir;

  /** `$XDG_CONFIG_HOME/opencode`, else `~/.config/opencode` (on every OS, as OpenCode does). */
  const configDir = (home: string): string => {
    const xdg = env.XDG_CONFIG_HOME;
    return xdg && path.isAbsolute(xdg)
      ? path.join(xdg, "opencode")
      : path.join(home, ".config", "opencode");
  };
  const jsonFile = (home: string): string => path.join(configDir(home), "opencode.json");
  const jsoncFile = (home: string): string => path.join(configDir(home), "opencode.jsonc");
  /** The config files that exist, `.json` first. */
  const existing = (home: string): string[] =>
    [jsonFile(home), jsoncFile(home)].filter((f) => fs.existsSync(f));

  const entry = (): { type: "local"; command: string[]; enabled: true } => ({
    type: "local",
    command: [...deps.command, "mcp"],
    enabled: true,
  });
  /**
   * True if agent-vault could have written `e`: a local server whose command ends in `mcp` and
   * starts with an absolute path or the bare name. Anything else under our name is the user's.
   */
  const isOurs = (e: Record<string, unknown>): boolean => {
    const cmd = e.command;
    if (e.type !== "local" || !Array.isArray(cmd) || cmd.length < 2) return false;
    const first = cmd[0];
    return (
      cmd[cmd.length - 1] === "mcp" &&
      typeof first === "string" &&
      (path.isAbsolute(first) || first === "agent-vault")
    );
  };
  const foreignBase = (file: string): string =>
    `${path.basename(file)} already has an "${MCP_NAME}" MCP entry that agent-vault did not write`;
  const foreign = (file: string): string =>
    `${foreignBase(file)}; remove or rename it, then run install again`;

  const sameEntry = (e: Record<string, unknown>): boolean => {
    const want = entry();
    return (
      e.type === want.type &&
      e.enabled === true &&
      Array.isArray(e.command) &&
      e.command.length === want.command.length &&
      e.command.every((w, i) => w === want.command[i])
    );
  };

  /** What install writes into a file that was not there. Uninstall deletes a file left like this. */
  const scaffold = (): string => `{\n  "$schema": "${OPENCODE_SCHEMA}"\n}\n`;

  const read = (file: string): string => fs.readFileSync(file, "utf8");

  /** The parsed file, or an `AdapterError` naming it if it is not JSON. */
  const parsed = (file: string, text: string): Record<string, unknown> => {
    try {
      return parseJson(text);
    } catch (err) {
      const why = err instanceof JsonEditError ? err.message : String(err);
      throw new AdapterError(`${file} is not usable (${why}); fix it by hand first`);
    }
  };

  /** Our entry in `root`, if any. Throws if `mcp` or the entry is not an object. */
  const entryOf = (file: string, root: Record<string, unknown>): Record<string, unknown> | null => {
    if (root.mcp === undefined) return null;
    if (!isRecord(root.mcp)) {
      throw new AdapterError(`${file}: "mcp" is not an object; fix it by hand first`);
    }
    const found = root.mcp[MCP_NAME];
    if (found === undefined) return null;
    if (!isRecord(found)) {
      throw new AdapterError(`${file}: "mcp.${MCP_NAME}" is not an object; fix it by hand first`);
    }
    return found;
  };

  const adapter: HarnessAdapter = {
    id: "opencode",

    async detect(home) {
      return fs.existsSync(configDir(home));
    },

    async install({ home, modelKey }: InstallOptions): Promise<InstallReport> {
      // Everything that can refuse comes before the first write.
      if (!path.isAbsolute(deps.command[0] ?? "")) {
        throw new AdapterError(
          "cannot tell where agent-vault is installed: run the built CLI (pnpm build) or the single-file binary",
        );
      }
      if (modelKey !== undefined) {
        throw new AdapterError(
          "--model-key only works for claude-code: OpenCode has no key helper",
        );
      }
      const files = existing(home);
      const texts = new Map(files.map((f) => [f, read(f)]));
      const found = files.map((f) => ({
        file: f,
        entry: entryOf(f, parsed(f, texts.get(f) as string)),
      }));

      const report: InstallReport = { harness: "opencode", files: [], backups: [], notes: [] };
      for (const f of found) {
        if (f.entry && !isOurs(f.entry)) throw new AdapterError(foreign(f.file));
      }
      const current = found.find((f) => f.entry !== null);
      if (current?.entry && sameEntry(current.entry)) {
        report.notes.push(`MCP server agent-vault was already registered in ${current.file}`);
        return report;
      }

      const target = current?.file ?? files[0] ?? jsonFile(home);
      const before = texts.get(target);
      const next = setAt(before ?? scaffold(), ["mcp", MCP_NAME], entry());
      if (before !== undefined) {
        report.backups.push(backupFile(target, backupsDir()));
        writeFileAtomic(target, next);
      } else {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, next);
      }
      report.files.push(target);
      report.notes.push(
        `MCP server agent-vault ${current ? "replaced" : "added"} in ${target}`,
        "prompt capture: not wired for OpenCode yet; use agent-vault grab to paste a key",
      );
      return report;
    },

    async uninstall(home) {
      for (const file of existing(home)) {
        const text = read(file);
        const mine = entryOf(file, parsed(file, text));
        if (mine === null) continue;
        if (!isOurs(mine)) {
          log(`${foreignBase(file)}; left it alone`);
          continue;
        }
        const next = removeAt(text, ["mcp", MCP_NAME]);
        backupFile(file, backupsDir());
        // A file install made holds nothing but what install put there.
        if (next === scaffold()) fs.rmSync(file);
        else writeFileAtomic(file, next);
      }
    },

    async doctor(home): Promise<DoctorReport> {
      const checks: DoctorCheck[] = [];
      const add = (name: string, ok: boolean, detail: string, fix?: string): void => {
        checks.push({ name, ok, detail, ...(fix !== undefined && !ok && { fix }) });
      };
      const reinstall = "agent-vault install opencode";

      // mcp
      try {
        const files = existing(home);
        const hit = files
          .map((file) => ({ file, entry: entryOf(file, parsed(file, read(file))) }))
          .find((f) => f.entry !== null);
        const e = hit?.entry;
        if (!hit || !e) {
          add("mcp", false, "agent-vault is not registered", reinstall);
        } else if (!isOurs(e)) {
          add("mcp", false, foreign(hit.file), `rename the entry, then ${reinstall}`);
        } else if (e.enabled === false) {
          add("mcp", false, `the entry in ${hit.file} is disabled`, reinstall);
        } else {
          const words = Array.isArray(e.command) ? e.command.map(String) : [];
          const gone = words.filter((w) => path.isAbsolute(w) && !fs.existsSync(w));
          if (words.length === 0) {
            add("mcp", false, `the entry in ${hit.file} has no command`, reinstall);
          } else if (gone.length > 0) {
            add("mcp", false, `the entry runs ${gone[0]}, which does not exist`, reinstall);
          } else {
            add("mcp", true, `agent-vault registered in ${hit.file}`);
          }
        }
      } catch (err) {
        add("mcp", false, (err as Error).message, reinstall);
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

      // what OpenCode cannot do yet: lines to read, not failures
      checks.push(
        { name: "prompt capture", ok: true, info: true, detail: PROMPT_CAPTURE },
        { name: "note", ok: true, info: true, detail: DB_NOTE },
      );

      return { harness: "opencode", ok: checks.every((c) => c.ok), checks };
    },

    async handleHook(): Promise<HookOutput> {
      return null;
    },

    historyFiles() {
      return [];
    },
  };
  return adapter;
}
