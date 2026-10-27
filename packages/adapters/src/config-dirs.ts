import path from "node:path";

/**
 * Where each harness keeps its config, given the environment variable that moves it. The
 * adapters (install, doctor) and the sources (migrate, scan) share these, so all agree.
 */

/** Claude Code's config dir: `$CLAUDE_CONFIG_DIR`, else `<home>/.claude`. */
export const claudeConfigDir = (home: string, configDir?: string): string =>
  configDir ? path.resolve(configDir) : path.join(home, ".claude");

/** Claude's user-scope config (MCP servers): inside `$CLAUDE_CONFIG_DIR` when set, else `<home>/.claude.json`. */
export const claudeGlobalFile = (home: string, configDir?: string): string =>
  configDir ? path.join(path.resolve(configDir), ".claude.json") : path.join(home, ".claude.json");

/** `$CODEX_HOME`, else `<home>/.codex`. */
export const codexHomeDir = (home: string, codexHome?: string): string =>
  codexHome ? path.resolve(codexHome) : path.join(home, ".codex");

/** `$XDG_CONFIG_HOME/opencode`, else `<home>/.config/opencode` (on every OS, as OpenCode does). */
export const opencodeConfigDir = (home: string, xdgConfigHome?: string): string =>
  xdgConfigHome && path.isAbsolute(xdgConfigHome)
    ? path.join(xdgConfigHome, "opencode")
    : path.join(home, ".config", "opencode");
