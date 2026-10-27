/**
 * The headless/CI unlock for the keyfile store (AGENTS.md). Interactive use reads the passphrase
 * from a TTY instead. It is never handed on to a child process.
 */
export const PASSPHRASE_ENV = "AGENT_VAULT_KEYFILE_PASSPHRASE";

/** `env` as a child's base environment: every variable that is set, except the keyfile passphrase. */
export function childBaseEnv(env: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (value !== undefined && key !== PASSPHRASE_ENV) out[key] = value;
  }
  return out;
}
