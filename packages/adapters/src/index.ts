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
  HELD_BACK_REASON,
  type HookClient,
  handlePromptSubmit,
  handleScrub,
  type PromptDecision,
  type PromptSubmitOptions,
  SCRUB_TIMEOUT_MS,
  type ScrubOptions,
  storedReason,
} from "./hook.js";
export {
  addHooks,
  appendHook,
  findHooks,
  type HookEntry,
  type HookSpec,
  quoteArg,
  quoteCommand,
  removeHookEntry,
  removeHooks,
  splitCommand,
} from "./hook-config.js";
export { appendAt, JsonEditError, type JsonPath, parseJson, removeAt, setAt } from "./json-edit.js";
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
