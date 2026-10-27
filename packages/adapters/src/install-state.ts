import fs from "node:fs";
import path from "node:path";
import { ensurePrivateDir } from "@agent-vault/platform";
import type { JsonPath } from "./json-edit.js";
import type { TomlEdit } from "./toml-edit.js";

/**
 * What an install did to one file, kept so an uninstall can undo exactly that and nothing else:
 * the command it wrote (so only entries with that prefix count as ours), the containers it had to
 * create (so a `hooks` object the user already had is not deleted), and whether it made the file.
 */
export type FileState = {
  /** The file did not exist before. Uninstall deletes it if nothing else is left in it. */
  createdFile: boolean;
  /** The file held only this white space before. Uninstall puts it back if nothing else is left. */
  whitespace?: string | undefined;
  /** Objects and arrays the install created, as paths. */
  created: JsonPath[];
  /** The quoted command words the install wrote, e.g. `/usr/bin/node /opt/av/main.js`. */
  prefix: string;
  /** Codex's `config.toml` is edited as text, not as JSON: the exact edits made, to undo. */
  toml?:
    | {
        /** "cli" if `codex mcp add` added the MCP table (uninstall runs `codex mcp remove`). */
        mcp: "cli" | null;
        edits: TomlEdit[];
        /** Trust keys whose hook changed under them, with the `trusted_hash` that went stale. */
        staleTrust: Record<string, string>;
        /** Where our hooks sat when last installed, `<event_snake>` to `<group>:<index>`: Codex keys trust by position. */
        slots?: Record<string, string> | undefined;
      }
    | undefined;
};

export type InstallState = { version: 1; files: Record<string, FileState> };

const empty = (): InstallState => ({ version: 1, files: {} });

export function loadState(file: string): InstallState {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8")) as InstallState;
    return parsed.version === 1 && typeof parsed.files === "object" && parsed.files !== null
      ? parsed
      : empty();
  } catch {
    return empty();
  }
}

/** Write the state (mode 0600, in a private directory), or delete the file once it is empty. */
export function saveState(file: string, state: InstallState): void {
  if (Object.keys(state.files).length === 0) {
    fs.rmSync(file, { force: true });
    return;
  }
  ensurePrivateDir(path.dirname(file));
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(tmp, file);
}

/** The recorded containers as a `prune` test. */
export const pruneFrom =
  (state: FileState | undefined) =>
  (container: JsonPath): boolean =>
    state?.created.some((c) => c.join("\0") === container.join("\0")) ?? false;
