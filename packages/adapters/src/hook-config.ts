import {
  appendAt,
  type JsonPath,
  missingContainers,
  type PruneFn,
  parseJson,
  removeAt,
} from "./json-edit.js";

/**
 * Hook entries in a harness's JSON config: `{ hooks: { <Event>: [ { hooks: [ { type, command,
 * timeout } ] } ] } }`. Claude Code's `settings.json` and Codex's `hooks.json` share this nesting.
 */

export type HookSpec = { event: string; command: string; timeout: number };

export type HookEntry = { event: string; command: string; group: number; index: number };

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const SAFE_ARG_RE = /^[A-Za-z0-9_@%+=:,./-]+$/;

/**
 * `arg` as one word of a shell command line. POSIX: single quotes, with `'` written `'\''`.
 * Windows: double quotes and forward slashes, which Git Bash, cmd.exe and node all accept.
 */
export function quoteArg(arg: string, platform: NodeJS.Platform = process.platform): string {
  if (platform === "win32") {
    const slashed = arg.replaceAll("\\", "/");
    return SAFE_ARG_RE.test(slashed) ? slashed : `"${slashed.replaceAll('"', '\\"')}"`;
  }
  return SAFE_ARG_RE.test(arg) ? arg : `'${arg.replaceAll("'", "'\\''")}'`;
}

export const quoteCommand = (argv: string[], platform?: NodeJS.Platform): string =>
  argv.map((a) => quoteArg(a, platform)).join(" ");

/** Split a command line into words, honouring single quotes, double quotes and `\` escapes. */
export function splitCommand(line: string): string[] {
  const words: string[] = [];
  let cur = "";
  let started = false;
  let quote: "'" | '"' | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i] as string;
    if (quote === "'") {
      if (ch === "'") quote = null;
      else cur += ch;
    } else if (quote === '"') {
      if (ch === '"') quote = null;
      else if (ch === "\\" && /["\\$`]/.test(line[i + 1] ?? "")) cur += line[++i];
      else cur += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      started = true;
    } else if (ch === "\\" && i + 1 < line.length) {
      cur += line[++i];
      started = true;
    } else if (/\s/.test(ch)) {
      if (started || cur) words.push(cur);
      cur = "";
      started = false;
    } else {
      cur += ch;
      started = true;
    }
  }
  if (started || cur) words.push(cur);
  return words;
}

/** Which hook commands are ours: contain this text, or satisfy this test. */
export type CommandMatch = string | ((command: string) => boolean);

const matcher = (match: CommandMatch): ((command: string) => boolean) =>
  typeof match === "string" ? (c) => c.includes(match) : match;

/** Every hook whose command matches, in file order. */
export function findHooks(text: string, match: CommandMatch): HookEntry[] {
  const isOurs = matcher(match);
  const hooks = parseJson(text).hooks;
  const out: HookEntry[] = [];
  if (!isRecord(hooks)) return out;
  for (const [event, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) continue;
    groups.forEach((group, g) => {
      const list = isRecord(group) ? group.hooks : undefined;
      if (!Array.isArray(list)) return;
      list.forEach((hook, index) => {
        if (isRecord(hook) && typeof hook.command === "string" && isOurs(hook.command)) {
          out.push({ event, command: hook.command, group: g, index });
        }
      });
    });
  }
  return out;
}

/**
 * Remove every matching hook, and the group around it when it was the only one in it. An event
 * list or `hooks` object that this empties goes too only if `prune` says an install created it.
 */
export function removeHooks(text: string, match: CommandMatch, prune?: PruneFn): string {
  let out = text;
  for (;;) {
    const hit = findHooks(out, match).at(-1); // the last one first: earlier indexes stay valid
    if (!hit) return out;
    const group = (parseJson(out).hooks as Record<string, unknown[]>)[hit.event]?.[hit.group];
    const alone = (group as { hooks: unknown[] }).hooks.length === 1;
    out = removeAt(
      out,
      alone ? ["hooks", hit.event, hit.group] : ["hooks", hit.event, hit.group, "hooks", hit.index],
      prune,
    );
  }
}

/**
 * Append each spec as a group of its own to its event's list, after removing the entries that
 * match (a second install replaces ours instead of duplicating it). Also says which containers
 * the install created: pass them to `removeHooks` as `prune` so an uninstall removes only those.
 */
export function addHooksTracked(
  text: string,
  specs: HookSpec[],
  match: CommandMatch,
  prune?: PruneFn,
): { text: string; created: JsonPath[] } {
  let out = removeHooks(text, match, prune);
  const created: JsonPath[] = [];
  for (const { event, command, timeout } of specs) {
    for (const path of missingContainers(out, ["hooks", event])) {
      if (!created.some((c) => c.join("\0") === path.join("\0"))) created.push(path);
    }
    out = appendAt(out, ["hooks", event], { hooks: [{ type: "command", command, timeout }] });
  }
  return { text: out, created };
}

/** Append `spec` as a group of its own to its event's list. Nothing else in the file moves. */
export function appendHook(text: string, { event, command, timeout }: HookSpec): string {
  return appendAt(text, ["hooks", event], { hooks: [{ type: "command", command, timeout }] });
}

/** Remove the one hook at `entry`'s place, and its group if that leaves it empty. */
export function removeHookEntry(
  text: string,
  entry: Pick<HookEntry, "event" | "group" | "index">,
): string {
  const group = (parseJson(text).hooks as Record<string, unknown[]>)[entry.event]?.[entry.group];
  const alone = (group as { hooks: unknown[] }).hooks.length === 1;
  return removeAt(
    text,
    alone
      ? ["hooks", entry.event, entry.group]
      : ["hooks", entry.event, entry.group, "hooks", entry.index],
  );
}
export const addHooks = (text: string, specs: HookSpec[], match: CommandMatch): string =>
  addHooksTracked(text, specs, match).text;
