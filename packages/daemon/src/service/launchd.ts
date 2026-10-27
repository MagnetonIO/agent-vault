import path from "node:path";

export const LABEL = "com.agent-vault.daemon";
const LAUNCHCTL = "/bin/launchctl";

export const plistPath = (home: string): string =>
  path.posix.join(home, "Library", "LaunchAgents", `${LABEL}.plist`);

const xml = (s: string): string =>
  s.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");

export type PlistOptions = {
  argv: readonly string[];
  logFile: string;
  /** Set only when `AGENT_VAULT_HOME` moves the vault; it is the only variable the service gets. */
  vaultHome: string | undefined;
};

export function renderPlist({ argv, logFile, vaultHome }: PlistOptions): string {
  const args = argv.map((a) => `    <string>${xml(a)}</string>`).join("\n");
  const env = vaultHome
    ? `  <key>EnvironmentVariables</key>
  <dict>
    <key>AGENT_VAULT_HOME</key>
    <string>${xml(vaultHome)}</string>
  </dict>
`
    : "";
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
${args}
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>StandardOutPath</key>
  <string>${xml(logFile)}</string>
  <key>StandardErrorPath</key>
  <string>${xml(logFile)}</string>
${env}</dict>
</plist>
`;
}

export const activateArgv = (uid: number, plist: string): string[] => [
  LAUNCHCTL,
  "bootstrap",
  `gui/${uid}`,
  plist,
];

export const deactivateArgv = (uid: number, plist: string): string[] => [
  LAUNCHCTL,
  "bootout",
  `gui/${uid}`,
  plist,
];
