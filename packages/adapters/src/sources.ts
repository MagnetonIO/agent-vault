import fs from "node:fs";
import path from "node:path";
import { parseEnvFile } from "@agent-vault/core";
import { type Detection, detectSecrets } from "@agent-vault/detect";
import { type ParseError, parse as parseJsonc } from "jsonc-parser";
import { parse as parseToml } from "smol-toml";
import { closingQuote, splitEnvLine } from "./dotenv.js";
import { lowerDashes, sanitizeName } from "./names.js";
import { parseWrapper } from "./wrap.js";

export type FindingKind =
  | "dotenv"
  | "claude-mcp"
  | "codex-mcp"
  | "opencode-mcp"
  | "opencode-remote-header"
  | "claude-remote-header";

/**
 * One plaintext secret. `locator` says where it sits, for people: `line <n>` in a dotenv file,
 * otherwise the dotted path (`mcpServers.github.env.GITHUB_TOKEN`). `jsonPath` is the same place
 * as segments, for edits (project paths hold dots and slashes); it is empty for dotenv. `envName`
 * is the variable or header name. `detection.value` IS the secret: keep findings in memory, never
 * print them.
 */
export type Finding = {
  file: string;
  kind: FindingKind;
  locator: string;
  envName: string;
  detection: Detection;
  jsonPath: (string | number)[];
};

export type Sources = {
  home: string;
  cwd: string;
  /** `$CODEX_HOME`; `<home>/.codex` when unset. */
  codexHome?: string | undefined;
  /** Told about anything that was skipped or needs a person, so a miss is never silent. */
  warn?: ((message: string) => void) | undefined;
};

type Warn = Sources["warn"];

/** Header findings are only listed for the later, proxy-based phase; nothing rewrites them. */
export const isRemoteHeader = (kind: FindingKind): boolean =>
  kind === "opencode-remote-header" || kind === "claude-remote-header";

const KEY_NAME_RE = /KEY|TOKEN|SECRET|PASSWORD/i;
/** `${NAME}` or `$NAME`: the harness expands it, so there is no secret in the file. */
const ENV_EXPANSION_RE = /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/;
const VAULT_SCHEME = "vault://";
/** Templates ship placeholders on purpose and are committed. */
const DOTENV_TEMPLATE_RE = /\.(?:example|sample|template|dist)$/i;
const DOTENV_RE = /^\.env(?:\..+)?$/;

/**
 * A value is a finding when a detection rule hits it, or its name says it is a secret. A
 * `vault://` reference, an env expansion or an empty value never is.
 */
export function classify(name: string, value: string): Detection | null {
  if (value === "" || value.startsWith(VAULT_SCHEME) || ENV_EXPANSION_RE.test(value)) return null;
  const hit = detectSecrets(value)[0];
  if (hit) return hit;
  if (!KEY_NAME_RE.test(name)) return null;
  return { ruleId: "key-name", value, start: 0, end: value.length, suggestedName: "" };
}

/** The file's text without a byte order mark, or null if it is absent. Symlinks are followed. */
function readText(file: string, warn?: Warn): string | null {
  try {
    if (!fs.statSync(file).isFile()) return null;
    return fs.readFileSync(file, "utf8").replace(/^\uFEFF/, "");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
      warn?.(`skipped ${file}: ${(err as Error).message}`);
    }
    return null;
  }
}

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

function stringEntries(table: unknown): [string, string][] {
  if (!isRecord(table)) return [];
  return Object.entries(table).filter((e): e is [string, string] => typeof e[1] === "string");
}

export function findInDotenv(file: string, warn?: Warn): Finding[] {
  const text = readText(file, warn);
  if (text === null) return [];
  const lines = text.split(/\r\n|\r|\n/);
  const out: Finding[] = [];
  // Lines up to here are the body of an earlier multi-line value, not entries of their own.
  let resumeAfter = 0;
  for (const entry of parseEnvFile(text)) {
    if (entry.line <= resumeAfter || entry.literal === undefined) continue;
    const split = splitEnvLine(lines[entry.line - 1] ?? "");
    if (split?.unclosed) {
      // A quote that does not close here runs on over the next lines (a PEM key, say). This tool
      // rewrites one line at a time, so it leaves the value alone and says where it is.
      const body = [split.rest.slice(1)];
      resumeAfter = lines.length;
      for (let i = entry.line; i < lines.length; i++) {
        const close = closingQuote((split.quote as string) + (lines[i] as string));
        if (close !== -1) {
          body.push((lines[i] as string).slice(0, close - 1));
          resumeAfter = i + 1;
          break;
        }
        body.push(lines[i] as string);
      }
      if (classify(entry.key, body.join("\n"))) {
        const project = path.basename(path.dirname(path.resolve(file)));
        const name = sanitizeName(`env/${project}/${lowerDashes(entry.key)}`);
        warn?.(`multiline value at ${file}:${entry.line}; move it with: agent-vault set ${name}`);
      }
      continue;
    }
    const detection = classify(entry.key, entry.literal);
    if (detection) {
      out.push({
        file,
        kind: "dotenv",
        locator: `line ${entry.line}`,
        envName: entry.key,
        detection,
        jsonPath: [],
      });
    }
  }
  return out;
}

function dotenvFiles(cwd: string): string[] {
  let names: string[];
  try {
    names = fs.readdirSync(cwd);
  } catch {
    return [];
  }
  return names
    .filter((n) => DOTENV_RE.test(n) && !DOTENV_TEMPLATE_RE.test(n))
    .sort()
    .map((n) => path.join(cwd, n));
}

type McpShape = {
  /** Where a stdio server keeps its environment. */
  envField: string;
  stdioKind: FindingKind;
  remoteKind: FindingKind;
  /** `[command, ...args]` of a stdio server; empty if it has no command. */
  argvOf(server: Record<string, unknown>): unknown[];
  isRemote(server: Record<string, unknown>): boolean;
};

const CLAUDE_SHAPE: McpShape = {
  envField: "env",
  stdioKind: "claude-mcp",
  remoteKind: "claude-remote-header",
  argvOf: (s) =>
    typeof s.command === "string" && s.command !== ""
      ? [s.command, ...(Array.isArray(s.args) ? s.args : [])]
      : [],
  isRemote: (s) => s.type === "http" || s.type === "sse" || typeof s.url === "string",
};

const OPENCODE_SHAPE: McpShape = {
  envField: "environment",
  stdioKind: "opencode-mcp",
  remoteKind: "opencode-remote-header",
  argvOf: (s) => (Array.isArray(s.command) && typeof s.command[0] === "string" ? s.command : []),
  isRemote: (s) => s.type === "remote",
};

/** Secrets in the servers under `container` (a path into the parsed file). */
function findInServers(
  file: string,
  root: unknown,
  container: string[],
  shape: McpShape,
  warn?: Warn,
): Finding[] {
  let servers: unknown = root;
  for (const key of container) servers = isRecord(servers) ? servers[key] : undefined;
  if (!isRecord(servers)) return [];
  const out: Finding[] = [];
  for (const [server, def] of Object.entries(servers)) {
    if (!isRecord(def)) continue;
    const remote = shape.isRemote(def);
    if (!remote) {
      const argv = shape.argvOf(def);
      if (argv.length === 0) continue;
      if (parseWrapper(argv).kind === "mcp") {
        warn?.(
          `${file}: ${server} runs agent-vault itself; move its secrets with: agent-vault set`,
        );
        continue;
      }
    }
    const field = remote ? "headers" : shape.envField;
    for (const [name, value] of stringEntries(def[field])) {
      const detection = classify(name, value);
      if (!detection) continue;
      out.push({
        file,
        kind: remote ? shape.remoteKind : shape.stdioKind,
        locator: [...container, server, field, name].join("."),
        envName: name,
        detection,
        jsonPath: [...container, server, field, name],
      });
    }
  }
  return out;
}

function findInJson(
  file: string,
  shape: McpShape,
  containerKey: string,
  opts: { projects: boolean },
  warn?: Warn,
): Finding[] {
  const text = readText(file, warn);
  if (text === null) return [];
  const errors: ParseError[] = [];
  const root = parseJsonc(text, errors, { allowTrailingComma: true });
  if (errors.length > 0) {
    warn?.(`skipped ${file}: not valid JSON`);
    return [];
  }
  const out = findInServers(file, root, [containerKey], shape, warn);
  // Claude Code keeps per-project servers under projects.<absolute path>.mcpServers.
  const projects = opts.projects && isRecord(root) ? root.projects : undefined;
  if (isRecord(projects)) {
    for (const project of Object.keys(projects)) {
      out.push(...findInServers(file, root, ["projects", project, containerKey], shape, warn));
    }
  }
  return out;
}

function findInCodexToml(file: string, warn?: Warn): Finding[] {
  const text = readText(file, warn);
  if (text === null) return [];
  let root: unknown;
  try {
    root = parseToml(text);
  } catch {
    warn?.(`skipped ${file}: not valid TOML`);
    return [];
  }
  return findInServers(file, root, ["mcp_servers"], CODEX_SHAPE, warn);
}

const CODEX_SHAPE: McpShape = { ...CLAUDE_SHAPE, stdioKind: "codex-mcp", isRemote: () => false };

export const codexHomeOf = (s: Pick<Sources, "home" | "codexHome">): string =>
  s.codexHome || path.join(s.home, ".codex");

/** Where OpenCode keeps its config: the project's own file, then the user's. */
function opencodeConfigs(s: Sources): string[] {
  const dirs = [s.cwd, path.join(s.home, ".config", "opencode")];
  return dirs.flatMap((d) => ["opencode.json", "opencode.jsonc"].map((n) => path.join(d, n)));
}

/** Every plaintext secret in the dotenv files, MCP configs and OpenCode configs. Reads only. */
export async function findPlaintextSecrets(sources: Sources): Promise<Finding[]> {
  const { home, cwd, warn } = sources;
  const out: Finding[] = [];
  for (const file of dotenvFiles(cwd)) out.push(...findInDotenv(file, warn));
  out.push(
    ...findInJson(
      path.join(cwd, ".mcp.json"),
      CLAUDE_SHAPE,
      "mcpServers",
      { projects: false },
      warn,
    ),
  );
  out.push(
    ...findInJson(
      path.join(home, ".claude.json"),
      CLAUDE_SHAPE,
      "mcpServers",
      { projects: true },
      warn,
    ),
  );
  out.push(...findInCodexToml(path.join(codexHomeOf(sources), "config.toml"), warn));
  for (const file of opencodeConfigs(sources)) {
    out.push(...findInJson(file, OPENCODE_SHAPE, "mcp", { projects: false }, warn));
  }
  return out;
}

const BINARY_EXT_RE = /\.(?:db|sqlite3?|db-wal|db-shm|sqlite-wal|sqlite-shm)$/i;

/** Every file under `root`, symlinks not followed. */
function walk(root: string, out: string[]): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch {
    return;
  }
  for (const e of entries) {
    const full = path.join(root, e.name);
    if (e.isDirectory()) walk(full, out);
    else if (e.isFile()) out.push(full);
  }
}

/** True if the first bytes hold a NUL: the file is not text. */
function looksBinary(file: string): boolean {
  let fd: number | undefined;
  try {
    fd = fs.openSync(file, "r");
    const buf = Buffer.alloc(4096);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    return buf.subarray(0, n).includes(0);
  } catch {
    return true;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export type HistorySources = {
  home: string;
  codexHome?: string | undefined;
  /** `$XDG_DATA_HOME`; OpenCode's data lives under it. `<home>/.local/share` is always checked. */
  xdgDataHome?: string | undefined;
};

/** Transcript and history files the harnesses keep, as text files that exist. */
export function historyFiles(s: HistorySources): string[] {
  const claude = path.join(s.home, ".claude");
  const codex = codexHomeOf(s);
  const found: string[] = [];

  const projects: string[] = [];
  walk(path.join(claude, "projects"), projects);
  found.push(...projects.filter((f) => f.endsWith(".jsonl")));
  found.push(path.join(claude, "history.jsonl"));

  found.push(path.join(codex, "history.jsonl"));
  walk(path.join(codex, "sessions"), found);

  const dataRoots = new Set([path.join(s.home, ".local", "share")]);
  if (s.xdgDataHome && path.isAbsolute(s.xdgDataHome)) dataRoots.add(s.xdgDataHome);
  for (const root of dataRoots) walk(path.join(root, "opencode"), found);

  return [...new Set(found)]
    .filter((f) => !BINARY_EXT_RE.test(f))
    .filter((f) => {
      try {
        return fs.statSync(f).isFile() && !looksBinary(f);
      } catch {
        return false;
      }
    })
    .sort();
}
