/** A failure with a message for the user and the exit code to leave with. No stack is printed. */
export class CliError extends Error {
  readonly exitCode: number;

  constructor(message: string, exitCode = 1) {
    super(message);
    this.name = "CliError";
    this.exitCode = exitCode;
  }
}

/** Wait until stdout and stderr have taken what was written, so an exit cannot cut it off. */
export async function drain(): Promise<void> {
  await Promise.all(
    [process.stdout, process.stderr].map(
      (stream) => new Promise<void>((resolve) => stream.write("", () => resolve())),
    ),
  );
}

export async function exitWith(code: number): Promise<never> {
  await drain();
  process.exit(code);
}
