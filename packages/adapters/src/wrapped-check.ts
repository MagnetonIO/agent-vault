import fs from "node:fs";
import path from "node:path";
import type { DoctorCheck } from "./adapter.js";
import { quoteCommand } from "./hook-config.js";
import { type McpConfigKind, mcpServers } from "./sources.js";
import { parseWrapper } from "./wrap.js";

/** True if a bare command name resolves on `env`'s PATH (with PATHEXT on Windows). */
function onPath(name: string, env: NodeJS.ProcessEnv, platform: NodeJS.Platform): boolean {
  const win = platform === "win32";
  const dirs = (env.PATH ?? env.Path ?? "").split(win ? ";" : ":").filter(Boolean);
  const exts = win ? ["", ...(env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";")] : [""];
  return dirs.some((dir) => exts.some((ext) => fs.existsSync(path.join(dir, `${name}${ext}`))));
}

/**
 * The first word of an agent-vault prefix that cannot run: an absolute path that does not exist,
 * or a bare first word not on PATH. A relative path is not judged (its base is the harness's cwd).
 */
function missingWord(
  words: unknown[],
  env: NodeJS.ProcessEnv,
  platform: NodeJS.Platform,
): string | undefined {
  return words.map(String).find((word, i) => {
    if (path.isAbsolute(word)) return !fs.existsSync(word);
    return i === 0 && !/[\\/]/.test(word) && !onPath(word, env, platform);
  });
}

export type WrappedCheckOptions = {
  /** The words agent-vault writes now; the fix points at them. */
  self: readonly string[];
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
};

/**
 * One `doctor` check over a harness's MCP config: every server that runs through agent-vault
 * (`migrate` wrapped it, or it is agent-vault's own) must start with a command that exists. A
 * server wrapped with the bare `agent-vault` fails unless that is on PATH. Green when there are none.
 */
export function wrappedServersCheck(
  files: string[],
  config: McpConfigKind,
  opts: WrappedCheckOptions,
): DoctorCheck {
  let wrapped = 0;
  const broken: string[] = [];
  for (const file of files) {
    for (const { server, argv } of mcpServers(file, config)) {
      const w = parseWrapper(argv, opts.self);
      if (w.kind === "none") continue;
      wrapped++;
      const gone = missingWord(argv.slice(0, w.words), opts.env, opts.platform);
      if (gone !== undefined)
        broken.push(`${server} in ${file} runs ${gone}, which does not exist`);
    }
  }
  const name = "wrapped MCP servers";
  if (broken.length === 0) {
    return {
      name,
      ok: true,
      detail:
        wrapped === 0 ? "none" : `${wrapped} run through agent-vault, and each command exists`,
    };
  }
  const more = broken.length > 1 ? ` (and ${broken.length - 1} more)` : "";
  return {
    name,
    ok: false,
    detail: `${broken[0]}${more}`,
    fix: `make each such server's command start with: ${quoteCommand([...opts.self], opts.platform)}`,
  };
}
