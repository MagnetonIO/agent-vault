export const WRAPPER = "agent-vault";

/** What a server's command already is, as far as agent-vault goes. */
export type Wrapped =
  | { kind: "none" }
  /** `agent-vault mcp`: agent-vault's own server, which has no bundle to put secrets in. */
  | { kind: "mcp" }
  /** `agent-vault run ...`, with the bundle if one is named (`--bundle X`, `--bundle=X`, `-b X`). */
  | { kind: "run"; bundle: string | null };

const isWrapperExe = (exe: unknown): boolean =>
  typeof exe === "string" &&
  /^agent-vault(?:\.exe|\.cmd)?$/i.test(exe.split(/[\\/]/).pop() as string);

export function parseWrapper(argv: unknown[]): Wrapped {
  if (!isWrapperExe(argv[0])) return { kind: "none" };
  if (argv[1] === "mcp") return { kind: "mcp" };
  if (argv[1] !== "run") return { kind: "none" };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") break;
    if ((a === "--bundle" || a === "-b") && typeof argv[i + 1] === "string") {
      return { kind: "run", bundle: argv[i + 1] as string };
    }
    if (typeof a === "string" && a.startsWith("--bundle=")) {
      return { kind: "run", bundle: a.slice("--bundle=".length) };
    }
  }
  return { kind: "run", bundle: null };
}

/**
 * `argv` run through `agent-vault run --bundle <bundle> --`. Already-wrapped commands are not
 * wrapped again: one with a bundle is left as it is, one without gets the flag.
 */
export function wrapArgv(argv: string[], bundle: string): string[] {
  const w = parseWrapper(argv);
  if (w.kind === "run" && w.bundle !== null) return argv;
  if (w.kind === "run") return [argv[0] as string, "run", "--bundle", bundle, ...argv.slice(2)];
  return [WRAPPER, "run", "--bundle", bundle, "--", ...argv];
}
