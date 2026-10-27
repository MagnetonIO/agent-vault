export {
  AdapterError,
  type DoctorCheck,
  type DoctorReport,
  type HarnessAdapter,
  type HarnessId,
  type HookOptions,
  type HookOutput,
  type InstallOptions,
  type InstallReport,
} from "./adapter.js";
export { backupFile, writeFileAtomic } from "./backup.js";
export {
  CLAUDE_HOOK_MARKER,
  type ClaudeCodeDeps,
  type ClaudeRunner,
  createClaudeCodeAdapter,
  type ProbeRunner,
  tagFirst,
  versionManagerOf,
} from "./claude-code.js";
export {
  CODEX_HOOK_MARKER,
  type CodexDeps,
  type CodexRunner,
  createCodexAdapter,
  TRUST_ACTION,
} from "./codex.js";
export {
  CHAINED_HOOK,
  checkDiff,
  type GuardHit,
  HOOK_MARKER,
  type HookResult,
  HooksPathError,
  installHook,
  scanDiff,
  uninstallHook,
} from "./guard.js";
export {
  EXPOSED_TAG,
  HOOK_DEADLINE_MS,
  type HookClient,
  handlePromptSubmit,
  handleScrub,
  heldBackReason,
  OVERSIZE_REASON,
  type PromptDecision,
  type PromptSubmitOptions,
  SCRUB_TIMEOUT_MS,
  type ScrubOptions,
  storedReason,
} from "./hook.js";
export {
  addHooks,
  addHooksTracked,
  appendHook,
  type CommandMatch,
  findHooks,
  type HookEntry,
  type HookSpec,
  quoteArg,
  quoteCommand,
  removeHookEntry,
  removeHooks,
  splitCommand,
} from "./hook-config.js";
export {
  type FileState,
  type InstallState,
  loadState,
  pruneFrom,
  saveState,
} from "./install-state.js";
export {
  appendAt,
  JsonEditError,
  type JsonPath,
  missingContainers,
  type PruneFn,
  parseJson,
  removeAt,
  setAt,
} from "./json-edit.js";
export {
  type ApplyOptions,
  applyMigration,
  type HistoryHit,
  type MigrateClient,
  type MigrationResult,
  sanitizeName,
  scanHistory,
} from "./migrate.js";
export {
  createOpenCodeAdapter,
  OPENCODE_SCHEMA,
  type OpenCodeDeps,
} from "./opencode.js";
export {
  codexHomeOf,
  type Finding,
  type FindingKind,
  findInDotenv,
  findPlaintextSecrets,
  type HistorySources,
  historyFiles,
  isRemoteHeader,
  type Sources,
} from "./sources.js";
export {
  appendTable,
  eolOf,
  insertUnderHeader,
  parseToml,
  type TomlEdit,
  TomlEditError,
  tomlArray,
  tomlString,
  undoEdit,
} from "./toml-edit.js";
export { parseWrapper, type Wrapped, wrapArgv } from "./wrap.js";
