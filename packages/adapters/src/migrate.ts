import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { type BundleInfo, parseEnvFile, parseRef, type SecretMeta } from "@agent-vault/core";
import type { IpcClient } from "@agent-vault/daemon";
import { detectSecrets, fingerprint } from "@agent-vault/detect";
import { getPaths } from "@agent-vault/platform";
import {
  applyEdits,
  type FormattingOptions,
  modify,
  type ParseError,
  parse as parseJsonc,
} from "jsonc-parser";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { backupFile, writeFileAtomic } from "./backup.js";
import { type Finding, type FindingKind, isRemoteHeader } from "./sources.js";

const NAME_MAX = 128;
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const WRAPPER = "agent-vault";

export type MigrateClient = Pick<IpcClient, "call">;

export type MigrationResult = { migrated: number; listedForPhase2: number; backups: string[] };

export type ApplyOptions = {
  /** Defaults to `getPaths().backupsDir`. */
  backupsDir?: string | undefined;
};

// ---------------------------------------------------------------------------------- names

/** One path segment of a secret name: lower case, `[a-z0-9._-]`, starting with an alphanumeric. */
function sanitizeSegment(raw: string): string {
  const s = raw
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[^a-z0-9]+/, "")
    .replace(/-{2,}/g, "-");
  return s === "" ? "x" : s;
}

/** A legal secret name made from `/`-separated parts. */
export function sanitizeName(name: string): string {
  const parts = name.split("/").map(sanitizeSegment);
  let out = parts.join("/");
  if (out.length > NAME_MAX) out = out.slice(0, NAME_MAX).replace(/[/.\-_]+$/, "");
  return parseRef(`vault://${out}`) === null ? "secret/unnamed" : out;
}

const lowerDashes = (env: string): string => env.toLowerCase().replace(/_/g, "-");

/** `base`, or `base-2`, `base-3`, … while the name is taken. Reserves the name it returns. */
function takeName(base: string, taken: Set<string>): string {
  let name = base;
  for (let n = 2; taken.has(name); n++) {
    const suffix = `-${n}`;
    name = `${base.slice(0, NAME_MAX - suffix.length)}${suffix}`;
  }
  taken.add(name);
  return name;
}

type Mcp = { section: string; field: string };
const MCP_LOCATORS: Partial<Record<FindingKind, Mcp>> = {
  "claude-mcp": { section: "mcpServers", field: "env" },
  "codex-mcp": { section: "mcp_servers", field: "env" },
  "opencode-mcp": { section: "mcp", field: "environment" },
};

/** The server a stdio MCP finding belongs to, read back out of its locator. */
function serverOf(f: Finding): string {
  const mcp = MCP_LOCATORS[f.kind];
  if (!mcp) throw new Error(`${f.kind} is not an MCP server finding`);
  return f.locator.slice(
    mcp.section.length + 1,
    f.locator.length - (mcp.field.length + f.envName.length + 2),
  );
}

function baseNameFor(f: Finding): string {
  if (f.kind === "dotenv") {
    if (f.detection.ruleId !== "key-name") return sanitizeName(f.detection.suggestedName);
    const project = path.basename(path.dirname(path.resolve(f.file)));
    return sanitizeName(`env/${project}/${lowerDashes(f.envName)}`);
  }
  return sanitizeName(`mcp/${serverOf(f)}/${lowerDashes(f.envName)}`);
}

// ----------------------------------------------------------------------------- dotenv

type DotenvTarget = { key: string; value: string; ref: string };

const ENV_LINE_RE = /^(﻿?\s*(?:export\s+)?)([^=]*?)(\s*=\s*)(.*)$/s;

/** The index just after the quote that closes the one at `s[0]`, or -1. */
function closingQuote(s: string): number {
  const quote = s[0];
  for (let i = 1; i < s.length; i++) {
    if (quote === '"' && s[i] === "\\") i++;
    else if (s[i] === quote) return i;
  }
  return -1;
}

/** `line` with only the value token replaced: quotes, `export`, spacing and comment stay. */
function rewriteEnvLine(line: string, target: DotenvTarget): string | null {
  const m = ENV_LINE_RE.exec(line);
  if (!m || m[2]?.trim() !== target.key) return null;
  const [, head = "", key = "", eq = "", rest = ""] = m;
  const quote = rest[0];
  let start: number;
  let end: number;
  if (quote === '"' || quote === "'") {
    const close = closingQuote(rest);
    start = 1;
    end = close === -1 ? rest.length : close;
  } else {
    const comment = /\s#/.exec(rest);
    start = 0;
    end = (comment ? rest.slice(0, comment.index) : rest).trimEnd().length;
  }
  return `${head}${key}${eq}${rest.slice(0, start)}${target.ref}${rest.slice(end)}`;
}

function rewriteDotenv(text: string, targets: Map<number, DotenvTarget>): string {
  // Odd entries are the line terminators, kept as they were (CRLF, LF or CR).
  const parts = text.split(/(\r\n|\r|\n)/);
  for (const [lineNo, target] of targets) {
    const at = (lineNo - 1) * 2;
    const rewritten = rewriteEnvLine(parts[at] ?? "", target);
    if (rewritten === null) throw new Error(`${lineNo}: could not locate ${target.key}`);
    parts[at] = rewritten;
  }
  const out = parts.join("");
  const entries = new Map(parseEnvFile(out).map((e) => [e.line, e]));
  for (const [lineNo, target] of targets) {
    const entry = entries.get(lineNo);
    if (entry?.key !== target.key || entry.ref !== target.ref.slice("vault://".length)) {
      throw new Error(`line ${lineNo}: rewriting ${target.key} did not give a vault:// reference`);
    }
  }
  return out;
}

// ------------------------------------------------------------------------------- MCP

/** `agent-vault run --bundle <b> --` already in front of a server: the bundle `<b>`. */
function wrappedBundle(argv: unknown[]): string | null {
  const [exe, run, flag, bundle] = argv;
  return exe === WRAPPER && run === "run" && flag === "--bundle" && typeof bundle === "string"
    ? bundle
    : null;
}

type ServerPlan = {
  server: string;
  bundle: string;
  create: boolean;
  /** env name -> secret name */
  grants: Map<string, string>;
};

const wrapArgs = (bundle: string): string[] => ["run", "--bundle", bundle, "--"];

function formattingOf(text: string): FormattingOptions {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const indent = /^([ \t]+)\S/m.exec(text)?.[1] ?? "  ";
  return indent.startsWith("\t")
    ? { insertSpaces: false, tabSize: 1, eol }
    : { insertSpaces: true, tabSize: indent.length, eol };
}

/** Wrap each planned server of a Claude (`mcpServers`) or OpenCode (`mcp`) JSON/JSONC config. */
function rewriteJson(text: string, kind: FindingKind, plans: ServerPlan[]): string {
  const mcp = MCP_LOCATORS[kind] as Mcp;
  const bom = text.startsWith("﻿") ? "﻿" : "";
  let out = bom ? text.slice(1) : text;
  const formattingOptions = formattingOf(out);
  const edit = (jsonPath: (string | number)[], value: unknown) => {
    out = applyEdits(out, modify(out, jsonPath, value, { formattingOptions }));
  };
  const defOf = (server: string): Record<string, unknown> => {
    const root = parseJsonc(out, [], { allowTrailingComma: true }) as Record<string, unknown>;
    return (root[mcp.section] as Record<string, Record<string, unknown>>)[server] as Record<
      string,
      unknown
    >;
  };

  for (const plan of plans) {
    const at = [mcp.section, plan.server];
    const def = defOf(plan.server);
    if (kind === "opencode-mcp") {
      const command = def.command as string[];
      if (wrappedBundle(command) === null) {
        edit([...at, "command"], [WRAPPER, ...wrapArgs(plan.bundle), ...command]);
      }
    } else {
      const args = Array.isArray(def.args) ? (def.args as string[]) : [];
      if (wrappedBundle([def.command, ...args]) === null) {
        edit([...at, "command"], WRAPPER);
        edit([...at, "args"], [...wrapArgs(plan.bundle), def.command as string, ...args]);
      }
    }
    for (const env of plan.grants.keys()) edit([...at, mcp.field, env], undefined);
    const left = defOf(plan.server)[mcp.field];
    if (left && typeof left === "object" && Object.keys(left).length === 0) {
      edit([...at, mcp.field], undefined);
    }
  }

  const errors: ParseError[] = [];
  parseJsonc(out, errors, { allowTrailingComma: true });
  if (errors.length > 0) throw new Error("the edited file is no longer valid JSON");
  return bom + out;
}

function rewriteToml(text: string, plans: ServerPlan[]): string {
  const root = parseToml(text) as { mcp_servers: Record<string, Record<string, unknown>> };
  for (const plan of plans) {
    const def = root.mcp_servers[plan.server] as Record<string, unknown>;
    const args = Array.isArray(def.args) ? (def.args as string[]) : [];
    if (wrappedBundle([def.command, ...args]) === null) {
      def.args = [...wrapArgs(plan.bundle), def.command as string, ...args];
      def.command = WRAPPER;
    }
    const env = def.env as Record<string, unknown> | undefined;
    if (env) {
      for (const name of plan.grants.keys()) delete env[name];
      if (Object.keys(env).length === 0) delete def.env;
    }
  }
  return stringifyToml(root);
}

// ---------------------------------------------------------------- checks and planning

/** The value the file holds for `f` right now, or undefined if it has moved or is gone. */
function currentValue(f: Finding, text: string): string | undefined {
  if (f.kind === "dotenv") {
    const line = Number(f.locator.slice("line ".length));
    const entry = parseEnvFile(text).find((e) => e.line === line && e.key === f.envName);
    return entry?.literal;
  }
  const mcp = MCP_LOCATORS[f.kind] as Mcp;
  const root: unknown =
    f.kind === "codex-mcp" ? parseToml(text) : parseJsonc(text, [], { allowTrailingComma: true });
  const servers = (root as Record<string, Record<string, Record<string, unknown>>>)?.[mcp.section];
  const value = (servers?.[serverOf(f)]?.[mcp.field] as Record<string, unknown> | undefined)?.[
    f.envName
  ];
  return typeof value === "string" ? value : undefined;
}

type Ledger = {
  taken: Set<string>;
  /** Secrets already named in this run, so one value is stored once. */
  byValue: Map<string, string>;
  /** name -> env grants, for every bundle that exists or is planned. */
  bundles: Map<string, Map<string, string>>;
  existing: Set<string>;
};

function planServers(
  group: Finding[],
  names: Map<Finding, string>,
  ledger: Ledger,
  argvOf: (server: string) => unknown[],
): ServerPlan[] {
  const byServer = new Map<string, Finding[]>();
  for (const f of group) byServer.set(serverOf(f), [...(byServer.get(serverOf(f)) ?? []), f]);
  const plans: ServerPlan[] = [];
  for (const [server, items] of byServer) {
    const grants = new Map(items.map((f) => [f.envName, names.get(f) as string]));
    for (const env of grants.keys()) {
      if (!ENV_NAME_RE.test(env))
        throw new Error(`${server}: ${env} cannot be an environment variable name in a bundle`);
    }
    const fits = (held: Map<string, string>) =>
      [...grants].every(([env, s]) => !held.has(env) || held.get(env) === s);
    let bundle = wrappedBundle(argvOf(server));
    if (bundle === null) {
      const base = `mcp-${sanitizeSegment(server).replace(/\//g, "-")}`;
      bundle = base;
      for (
        let n = 2;
        ledger.bundles.has(bundle) && !fits(ledger.bundles.get(bundle) as Map<string, string>);
        n++
      ) {
        bundle = `${base}-${n}`;
      }
    }
    const create = !ledger.bundles.has(bundle);
    const held = ledger.bundles.get(bundle) ?? new Map<string, string>();
    for (const [env, s] of grants) held.set(env, s);
    ledger.bundles.set(bundle, held);
    plans.push({ server, bundle, create, grants });
  }
  return plans;
}

/** argv of a server as it stands in the file: `[command, ...args]`. */
function argvReader(f: Finding, text: string): (server: string) => unknown[] {
  const mcp = MCP_LOCATORS[f.kind] as Mcp;
  const root = (
    f.kind === "codex-mcp" ? parseToml(text) : parseJsonc(text, [], { allowTrailingComma: true })
  ) as Record<string, Record<string, Record<string, unknown>>>;
  return (server) => {
    const def = root[mcp.section]?.[server] ?? {};
    if (f.kind === "opencode-mcp") return Array.isArray(def.command) ? def.command : [];
    return [def.command, ...(Array.isArray(def.args) ? def.args : [])];
  };
}

const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");

/**
 * Move the plaintext in `findings` into the vault and rewrite the files that held it. Per file:
 * check it still holds what was found, work out the rewrite, back it up, store the secrets, make
 * the bundles, then replace the file atomically. Remote headers are counted, never touched.
 */
export async function applyMigration(
  findings: Finding[],
  client: MigrateClient,
  opts: ApplyOptions = {},
): Promise<MigrationResult> {
  const result: MigrationResult = {
    migrated: 0,
    listedForPhase2: findings.filter((f) => isRemoteHeader(f.kind)).length,
    backups: [],
  };
  const actionable = findings.filter((f) => !isRemoteHeader(f.kind));
  if (actionable.length === 0) return result;

  const backupsDir = opts.backupsDir ?? getPaths().backupsDir;
  const taken = new Set((await client.call<SecretMeta[]>("secret.list")).map((s) => s.name));
  const bundleList = actionable.some((f) => f.kind !== "dotenv")
    ? await client.call<BundleInfo[]>("bundle.list")
    : [];
  const ledger: Ledger = {
    taken,
    byValue: new Map(),
    bundles: new Map(bundleList.map((b) => [b.name, new Map(Object.entries(b.env))])),
    existing: new Set(bundleList.map((b) => b.name)),
  };

  const byFile = new Map<string, Finding[]>();
  for (const f of actionable) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f]);

  for (const [file, group] of byFile) {
    const kind = (group[0] as Finding).kind;
    if (group.some((f) => f.kind !== kind)) throw new Error(`${file}: findings of mixed kinds`);
    const text = fs.readFileSync(file, "utf8");
    for (const f of group) {
      if (currentValue(f, text) !== f.detection.value) {
        throw new Error(
          `${file} changed since it was scanned (${f.locator}); nothing was changed there`,
        );
      }
    }

    // Names first (so nothing is stored for a file that cannot be rewritten), then the rewrite.
    const names = new Map<Finding, string>();
    const fresh: { name: string; finding: Finding }[] = [];
    for (const f of group) {
      let name = ledger.byValue.get(f.detection.value);
      if (name === undefined) {
        name = takeName(baseNameFor(f), ledger.taken);
        ledger.byValue.set(f.detection.value, name);
        fresh.push({ name, finding: f });
      }
      names.set(f, name);
    }

    let plans: ServerPlan[] = [];
    let rewritten: string;
    if (kind === "dotenv") {
      const targets = new Map<number, DotenvTarget>();
      for (const f of group) {
        targets.set(Number(f.locator.slice("line ".length)), {
          key: f.envName,
          value: f.detection.value,
          ref: `vault://${names.get(f)}`,
        });
      }
      rewritten = rewriteDotenv(text, targets);
    } else {
      plans = planServers(group, names, ledger, argvReader(group[0] as Finding, text));
      rewritten = kind === "codex-mcp" ? rewriteToml(text, plans) : rewriteJson(text, kind, plans);
    }

    result.backups.push(backupFile(file, backupsDir));
    for (const { name, finding } of fresh) {
      await client.call("secret.put", {
        name,
        valueB64: b64(finding.detection.value),
        type: finding.detection.ruleId === "key-name" ? "generic" : finding.detection.ruleId,
      });
    }
    for (const plan of plans) {
      if (plan.create && !ledger.existing.has(plan.bundle)) {
        await client.call("bundle.create", { name: plan.bundle });
        ledger.existing.add(plan.bundle);
      }
      for (const [env, secret] of plan.grants) {
        await client.call("bundle.grant", { bundle: plan.bundle, env, secret });
      }
    }
    writeFileAtomic(file, rewritten);
    result.migrated += group.length;
  }
  return result;
}

// ------------------------------------------------------------------------------ scan

export type HistoryHit = { file: string; fingerprints: string[] };

/**
 * Look for secrets in transcript and history files, line by line. Reports each distinct secret
 * once per file, as a fingerprint (`ruleId len=N sha256:XXXXXXXX`); a value is never returned.
 */
export async function scanHistory(
  harnessFiles: string[],
  opts: { warn?: ((message: string) => void) | undefined } = {},
): Promise<HistoryHit[]> {
  const hits: HistoryHit[] = [];
  for (const file of harnessFiles) {
    const seen = new Set<string>();
    const input = fs.createReadStream(file, { encoding: "utf8" });
    try {
      for await (const line of readline.createInterface({ input, crlfDelay: Infinity })) {
        for (const d of detectSecrets(line)) seen.add(fingerprint(d));
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        opts.warn?.(`skipped ${file}: ${(err as Error).message}`);
      }
      continue;
    }
    if (seen.size > 0) hits.push({ file, fingerprints: [...seen].sort() });
  }
  return hits;
}
