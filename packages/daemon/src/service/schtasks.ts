import path from "node:path";

export const TASK_NAME = "agent-vault-daemon";

/** Absolute path of schtasks.exe, so a hostile PATH entry cannot stand in for it. */
export function schtasksExe(env: NodeJS.ProcessEnv = process.env): string {
  return path.win32.join(env.SystemRoot ?? "C:\\Windows", "System32", "schtasks.exe");
}

/** The arguments of the task's command line. Only words with whitespace or a quote are quoted. */
export function quoteCommand(argv: readonly string[]): string {
  return argv
    .map((a) => (/[\s"]/.test(a) || a === "" ? `"${a.replaceAll('"', '\\"')}"` : a))
    .join(" ");
}

const xml = (s: string): string =>
  s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");

export type TaskXmlOptions = {
  argv: readonly string[];
  /** `DOMAIN\user` (or just the user name) the task runs for. */
  user: string;
};

/**
 * The task definition for `schtasks /Create /XML`. The flags of `/Create` cannot express the
 * settings a daemon needs: by default Task Scheduler kills a task after 72 hours and does not
 * start it on battery.
 */
export function renderTaskXml({ argv, user }: TaskXmlOptions): string {
  const [command = "", ...args] = argv;
  return `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>agent-vault daemon (vaultd)</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>${xml(user)}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>${xml(user)}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>3</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>${xml(command)}</Command>
      <Arguments>${xml(quoteCommand(args))}</Arguments>
    </Exec>
  </Actions>
</Task>
`;
}

/** What schtasks reads: UTF-16 LE with a byte order mark, as the XML declaration says. */
export const encodeTaskXml = (text: string): Buffer =>
  Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]);

export const createArgv = (exe: string, xmlFile: string): string[] => [
  exe,
  "/Create",
  "/TN",
  TASK_NAME,
  "/XML",
  xmlFile,
  "/F",
];

export const queryArgv = (exe: string): string[] => [exe, "/Query", "/TN", TASK_NAME];

export const deleteArgv = (exe: string): string[] => [exe, "/Delete", "/TN", TASK_NAME, "/F"];
