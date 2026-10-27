import path from "node:path";

export const UNIT_NAME = "agent-vault.service";

export const unitPath = (home: string): string =>
  path.posix.join(home, ".config", "systemd", "user", UNIT_NAME);

/**
 * One word for ExecStart= or Environment=. systemd splits on whitespace, honours double quotes,
 * and expands `%` specifiers and `$` variables in both places, so those are doubled. A word with
 * anything beyond plain path characters is quoted.
 */
const word = (s: string): string => {
  const plain = s.replaceAll("%", "%%").replaceAll("$", "$$$$");
  if (/^[\w@+=:,./%$-]+$/.test(plain)) return plain;
  return `"${plain.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
};

export type UnitOptions = {
  argv: readonly string[];
  /** Set only when `AGENT_VAULT_HOME` moves the vault; it is the only variable the service gets. */
  vaultHome: string | undefined;
};

export function renderUnit({ argv, vaultHome }: UnitOptions): string {
  const env = vaultHome ? `Environment=${word(`AGENT_VAULT_HOME=${vaultHome}`)}\n` : "";
  return `[Unit]
Description=agent-vault daemon (vaultd)

[Service]
Type=simple
ExecStart=${argv.map(word).join(" ")}
Restart=on-failure
${env}
[Install]
WantedBy=default.target
`;
}

export const activateArgvs = (): string[][] => [
  ["systemctl", "--user", "daemon-reload"],
  ["systemctl", "--user", "enable", "--now", UNIT_NAME],
];

export const deactivateArgvs = (): string[][] => [
  ["systemctl", "--user", "disable", "--now", UNIT_NAME],
  ["systemctl", "--user", "daemon-reload"],
];
