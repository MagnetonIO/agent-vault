import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";
import { type BundleInfo, isValidEnvName, parseEnvFile, type SecretMeta } from "@agent-vault/core";
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
import { splitEnvLine } from "./dotenv.js";
import { bundleBase, isLegalName, lowerDashes, NAME_MAX, sanitizeName, suffixed } from "./names.js";
import { type Finding, type FindingKind, isRemoteHeader } from "./sources.js";
import { parseWrapper, WRAPPER, wrapArgv } from "./wrap.js";

export { sanitizeName } from "./names.js";

const VAULT_PREFIX = "vault://";

export type MigrateClient = Pick<IpcClient, "call">;

export type MigrationResult = {
  migrated: number;
  listedForPhase2: number;
  /** Copies of the files before they were changed. They hold the plaintext. */
  backups: string[];
  /** Files rewritten from a parsed copy (TOML), so comments and layout are gone. */
  reformatted: { file: string; backup: string }[];
};

export type ApplyOptions = {
  /** Defaults to `getPaths().backupsDir`. */
  backupsDir?: string | undefined;
  /**
   * How a wrapped server runs agent-vault: absolute words (`[node, /abs/main.js]` or the
   * single-file binary), since agent-vault is not on PATH. Default the bare `agent-vault`.
   */
  command?: readonly string[] | undefined;
};

type JsonPath = (string | number)[];

// ---------------------------------------------------------------------------------- names

/** `base`, or `base-2`, `base-3`, … while the name is taken. Reserves the name it returns. */
function takeName(base: string, taken: Set<string>): string {
  let name = base;
  for (let n = 2; taken.has(name); n++) name = suffixed(base, n);
  taken.add(name);
  return name;
}

function baseNameFor(f: Finding): string {
  if (f.kind === "dotenv") {
    if (f.detection.ruleId !== "key-name") return sanitizeName(f.detection.suggestedName);
    const project = path.basename(path.dirname(path.resolve(f.file)));
    return sanitizeName(`env/${project}/${lowerDashes(f.envName)}`);
  }
  return sanitizeName(`mcp/${serverNameOf(f)}/${lowerDashes(f.envName)}`);
}

// A stdio finding's path ends `[..., <server>, <env field>, <NAME>]`.
const serverPathOf = (f: Finding): JsonPath => f.jsonPath.slice(0, -2);
const serverNameOf = (f: Finding): string => String(f.jsonPath[f.jsonPath.length - 3]);
const fieldOf = (f: Finding): string => String(f.jsonPath[f.jsonPath.length - 2]);

function getAt(root: unknown, at: JsonPath): unknown {
  let node = root;
  for (const key of at) {
    if (typeof node !== "object" || node === null) return undefined;
    node = (node as Record<string | number, unknown>)[key];
  }
  return node;
}

const parseConfig = (kind: FindingKind, text: string): unknown => {
  const bomless = text.replace(/^\uFEFF/, "");
  return kind === "codex-mcp"
    ? parseToml(bomless)
    : parseJsonc(bomless, [], { allowTrailingComma: true });
};

// ----------------------------------------------------------------------------- dotenv

type DotenvTarget = { key: string; ref: string };

/** `line` with only the value token replaced: quotes, `export`, spacing and comment stay. */
function rewriteEnvLine(line: string, target: DotenvTarget): string | null {
  const split = splitEnvLine(line);
  if (!split || split.key.trim() !== target.key) return null;
  if (split.unclosed) throw new Error(`${target.key}: the quote opened on this line never closes`);
  const { head, key, eq, rest, start, end } = split;
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
    if (entry?.key !== target.key || entry.ref !== target.ref.slice(VAULT_PREFIX.length)) {
      throw new Error(`line ${lineNo}: rewriting ${target.key} did not give a vault:// reference`);
    }
  }
  return out;
}

// ------------------------------------------------------------------------------- MCP

type ServerPlan = {
  serverPath: JsonPath;
  server: string;
  field: string;
  bundle: string;
  create: boolean;
  /** env name -> secret name */
  grants: Map<string, string>;
};

/** `[command, ...args]` as a server stands in the file; OpenCode keeps it all in `command`. */
function argvOf(kind: FindingKind, def: unknown): string[] {
  const d = (def ?? {}) as Record<string, unknown>;
  if (kind === "opencode-mcp") return Array.isArray(d.command) ? (d.command as string[]) : [];
  return [d.command as string, ...(Array.isArray(d.args) ? (d.args as string[]) : [])];
}

function formattingOf(text: string): FormattingOptions {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const indent = /^([ \t]+)\S/m.exec(text)?.[1] ?? "  ";
  return indent.startsWith("\t")
    ? { insertSpaces: false, tabSize: 1, eol }
    : { insertSpaces: true, tabSize: indent.length, eol };
}

/** Wrap each planned server of a Claude or OpenCode JSON/JSONC config. */
function rewriteJson(
  text: string,
  kind: FindingKind,
  plans: ServerPlan[],
  self: readonly string[],
): string {
  const bom = text.startsWith("\uFEFF") ? "\uFEFF" : "";
  let out = bom ? text.slice(1) : text;
  const formattingOptions = formattingOf(out);
  const edit = (at: JsonPath, value: unknown) => {
    out = applyEdits(out, modify(out, at, value, { formattingOptions }));
  };
  const read = (at: JsonPath) => getAt(parseJsonc(out, [], { allowTrailingComma: true }), at);

  for (const plan of plans) {
    const argv = argvOf(kind, read(plan.serverPath));
    const wrapped = wrapArgv(argv, plan.bundle, self);
    if (wrapped !== argv) {
      if (kind === "opencode-mcp") {
        edit([...plan.serverPath, "command"], wrapped);
      } else {
        edit([...plan.serverPath, "command"], wrapped[0]);
        edit([...plan.serverPath, "args"], wrapped.slice(1));
      }
    }
    const envPath = [...plan.serverPath, plan.field];
    for (const env of plan.grants.keys()) edit([...envPath, env], undefined);
    const left = read(envPath);
    if (left && typeof left === "object" && Object.keys(left).length === 0) {
      edit(envPath, undefined);
    }
  }

  const errors: ParseError[] = [];
  parseJsonc(out, errors, { allowTrailingComma: true });
  if (errors.length > 0) throw new Error("the edited file is no longer valid JSON");
  return bom + out;
}

function rewriteToml(text: string, plans: ServerPlan[], self: readonly string[]): string {
  const root = parseToml(text.replace(/^\uFEFF/, ""));
  for (const plan of plans) {
    const def = getAt(root, plan.serverPath) as Record<string, unknown>;
    const argv = argvOf("codex-mcp", def);
    const wrapped = wrapArgv(argv, plan.bundle, self);
    if (wrapped !== argv) {
      def.command = wrapped[0];
      def.args = wrapped.slice(1);
    }
    const env = def[plan.field] as Record<string, unknown> | undefined;
    if (env) {
      for (const name of plan.grants.keys()) delete env[name];
      if (Object.keys(env).length === 0) delete def[plan.field];
    }
  }
  return stringifyToml(root);
}

// ---------------------------------------------------------------- checks and planning

/** The value the file holds for `f` right now, or undefined if it has moved or is gone. */
function currentValue(f: Finding, text: string): string | undefined {
  if (f.kind === "dotenv") {
    const line = Number(f.locator.slice("line ".length));
    return parseEnvFile(text).find((e) => e.line === line && e.key === f.envName)?.literal;
  }
  const value = getAt(parseConfig(f.kind, text), f.jsonPath);
  return typeof value === "string" ? value : undefined;
}

type Ledger = {
  taken: Set<string>;
  /** Secrets already named in this run, so one value is stored once. */
  byValue: Map<string, string>;
  /** name -> env grants, for every bundle that exists or is planned. */
  bundles: Map<string, Map<string, string>>;
  existing: Set<string>;
  /** How a wrapped server runs agent-vault (`ApplyOptions.command`). */
  self: readonly string[];
};

function planServers(
  kind: FindingKind,
  group: Finding[],
  names: Map<Finding, string>,
  ledger: Ledger,
  root: unknown,
): ServerPlan[] {
  const byServer = new Map<string, Finding[]>();
  for (const f of group) {
    const key = JSON.stringify(serverPathOf(f));
    byServer.set(key, [...(byServer.get(key) ?? []), f]);
  }
  const plans: ServerPlan[] = [];
  for (const items of byServer.values()) {
    const first = items[0] as Finding;
    const server = serverNameOf(first);
    const serverPath = serverPathOf(first);
    const grants = new Map(items.map((f) => [f.envName, names.get(f) as string]));
    for (const env of grants.keys()) {
      if (!isValidEnvName(env)) {
        throw new Error(`${server}: ${env} cannot be an environment variable name in a bundle`);
      }
    }
    const fits = (held: Map<string, string>) =>
      [...grants].every(([env, s]) => !held.has(env) || held.get(env) === s);

    const wrapper = parseWrapper(argvOf(kind, getAt(root, serverPath)), ledger.self);
    let bundle: string;
    if (wrapper.kind === "run" && wrapper.bundle !== null) {
      bundle = wrapper.bundle;
    } else {
      const base = bundleBase(server);
      bundle = base;
      for (
        let n = 2;
        ledger.bundles.has(bundle) && !fits(ledger.bundles.get(bundle) as Map<string, string>);
        n++
      ) {
        bundle = suffixed(base, n);
      }
    }
    if (!isLegalName(bundle)) throw new Error(`${server}: "${bundle}" is not a legal bundle name`);

    const create = !ledger.bundles.has(bundle);
    const held = ledger.bundles.get(bundle) ?? new Map<string, string>();
    for (const [env, s] of grants) held.set(env, s);
    ledger.bundles.set(bundle, held);
    plans.push({ serverPath, server, field: fieldOf(first), bundle, create, grants });
  }
  return plans;
}

const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");

type FilePlan = {
  file: string;
  count: number;
  rewritten: string;
  /** Secrets to store for this file (a value already named earlier in the run is not here). */
  fresh: { name: string; finding: Finding }[];
  plans: ServerPlan[];
  reformatted: boolean;
};

/** Check one file against its findings and work out its new text. Touches nothing. */
function planFile(file: string, group: Finding[], ledger: Ledger): FilePlan {
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

  const names = new Map<Finding, string>();
  const fresh: FilePlan["fresh"] = [];
  for (const f of group) {
    let name = ledger.byValue.get(f.detection.value);
    if (name === undefined) {
      name = takeName(baseNameFor(f), ledger.taken);
      if (!isLegalName(name) || name.length > NAME_MAX) {
        throw new Error(`${file}: "${name}" is not a legal secret name`);
      }
      ledger.byValue.set(f.detection.value, name);
      fresh.push({ name, finding: f });
    }
    names.set(f, name);
  }

  if (kind === "dotenv") {
    const targets = new Map<number, DotenvTarget>();
    for (const f of group) {
      targets.set(Number(f.locator.slice("line ".length)), {
        key: f.envName,
        ref: `${VAULT_PREFIX}${names.get(f)}`,
      });
    }
    return {
      file,
      count: group.length,
      rewritten: rewriteDotenv(text, targets),
      fresh,
      plans: [],
      reformatted: false,
    };
  }
  const plans = planServers(kind, group, names, ledger, parseConfig(kind, text));
  const toml = kind === "codex-mcp";
  return {
    file,
    count: group.length,
    rewritten: toml
      ? rewriteToml(text, plans, ledger.self)
      : rewriteJson(text, kind, plans, ledger.self),
    fresh,
    plans,
    reformatted: toml,
  };
}

/**
 * Move the plaintext in `findings` into the vault and rewrite the files that held it. Every file
 * is checked and every name and rewrite worked out first, so a problem is found before anything
 * is backed up or stored. Then, per file: back it up, store the secrets, make the bundles, and
 * replace the file atomically. Remote headers are counted, never touched.
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
    reformatted: [],
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
    self: opts.command ?? [WRAPPER],
  };

  const byFile = new Map<string, Finding[]>();
  for (const f of actionable) byFile.set(f.file, [...(byFile.get(f.file) ?? []), f]);
  const filePlans = [...byFile].map(([file, group]) => planFile(file, group, ledger));

  for (const plan of filePlans) {
    const backup = backupFile(plan.file, backupsDir);
    result.backups.push(backup);
    if (plan.reformatted) result.reformatted.push({ file: plan.file, backup });
    for (const { name, finding } of plan.fresh) {
      await client.call("secret.put", {
        name,
        valueB64: b64(finding.detection.value),
        type: finding.detection.ruleId === "key-name" ? "generic" : finding.detection.ruleId,
      });
    }
    for (const server of plan.plans) {
      if (server.create && !ledger.existing.has(server.bundle)) {
        await client.call("bundle.create", { name: server.bundle });
        ledger.existing.add(server.bundle);
      }
      for (const [env, secret] of server.grants) {
        await client.call("bundle.grant", { bundle: server.bundle, env, secret });
      }
    }
    writeFileAtomic(plan.file, plan.rewritten);
    result.migrated += plan.count;
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
