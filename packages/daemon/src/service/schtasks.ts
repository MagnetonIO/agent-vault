import path from "node:path";
import { ServiceError } from "./errors.js";

export const TASK_NAME = "agent-vault-daemon";

/** schtasks refuses a /TR longer than this. */
const MAX_TR = 261;

/** Absolute path of schtasks.exe, so a hostile PATH entry cannot stand in for it. */
export function schtasksExe(env: NodeJS.ProcessEnv = process.env): string {
  return path.win32.join(env.SystemRoot ?? "C:\\Windows", "System32", "schtasks.exe");
}

/** The command line of the task. Only words with whitespace or a quote are quoted. */
export function quoteCommand(argv: readonly string[]): string {
  return argv
    .map((a) => (/[\s"]/.test(a) || a === "" ? `"${a.replaceAll('"', '\\"')}"` : a))
    .join(" ");
}

export function createArgv(exe: string, argv: readonly string[]): string[] {
  const command = quoteCommand(argv);
  if (command.length > MAX_TR) {
    throw new ServiceError(
      `the daemon command is ${command.length} characters; Task Scheduler takes at most ${MAX_TR}. Install the CLI under a shorter path`,
    );
  }
  return [
    exe,
    "/Create",
    "/SC",
    "ONLOGON",
    "/TN",
    TASK_NAME,
    "/TR",
    command,
    "/RL",
    "LIMITED",
    "/F",
  ];
}

export const deleteArgv = (exe: string): string[] => [exe, "/Delete", "/TN", TASK_NAME, "/F"];
