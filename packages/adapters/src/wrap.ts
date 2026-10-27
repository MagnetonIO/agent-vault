export const WRAPPER = "agent-vault";

/** What a server's command already is, as far as agent-vault goes. */
export type Wrapped =
  | { kind: "none" }
  /** `agent-vault mcp`: agent-vault's own server, which has no bundle to put secrets in. */
  | { kind: "mcp"; words: number }
  /**
   * `agent-vault run ...`, with the bundle if one is named (`--bundle X`, `--bundle=X`, `-b X`).
   * `words` is how many leading words run agent-vault (see `wrapperWords`).
   */
  | { kind: "run"; bundle: string | null; words: number };

const basename = (word: unknown): string =>
  typeof word === "string" ? (word.split(/[\\/]/).pop() as string) : "";

/** The agent-vault binary by name: bare on PATH, or the single-file binary at a path. */
const isWrapperExe = (word: unknown): boolean =>
  /^agent-vault(?:\.exe|\.cmd)?$/i.test(basename(word));
const isNode = (word: unknown): boolean => /^node(?:js)?(?:\.exe)?$/i.test(basename(word));
/** The built CLI entry: `packages/cli/dist/main.js` in a checkout, `@agent-vault/cli/dist/…` installed. */
const isCliEntry = (word: unknown): boolean =>
  typeof word === "string" && /[\\/]cli[\\/]dist[\\/]main\.[cm]?js$/i.test(word);

/**
 * How many leading words of `argv` run agent-vault, or 0: `self` (the words this process would
 * write) exactly, the binary by name (`agent-vault`, or the single-file binary at any path), or
 * node plus the built CLI entry.
 */
export function wrapperWords(argv: unknown[], self: readonly string[] = []): number {
  if (self.length > 0 && self.every((w, i) => argv[i] === w)) return self.length;
  if (isWrapperExe(argv[0])) return 1;
  if (isNode(argv[0]) && isCliEntry(argv[1])) return 2;
  return 0;
}

export function parseWrapper(argv: unknown[], self: readonly string[] = []): Wrapped {
  const words = wrapperWords(argv, self);
  if (words === 0) return { kind: "none" };
  if (argv[words] === "mcp") return { kind: "mcp", words };
  if (argv[words] !== "run") return { kind: "none" };
  for (let i = words + 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") break;
    if ((a === "--bundle" || a === "-b") && typeof argv[i + 1] === "string") {
      return { kind: "run", bundle: argv[i + 1] as string, words };
    }
    if (typeof a === "string" && a.startsWith("--bundle=")) {
      return { kind: "run", bundle: a.slice("--bundle=".length), words };
    }
  }
  return { kind: "run", bundle: null, words };
}

/**
 * `argv` run through `<self> run --bundle <bundle> --`, where `self` is how to run agent-vault
 * (absolute words from the CLI; the bare name only as a default for tests). Already-wrapped
 * commands are not wrapped again: one with a bundle is left as it is, one without gets the flag.
 */
export function wrapArgv(
  argv: string[],
  bundle: string,
  self: readonly string[] = [WRAPPER],
): string[] {
  const w = parseWrapper(argv, self);
  if (w.kind === "run" && w.bundle !== null) return argv;
  if (w.kind === "run") {
    return [...argv.slice(0, w.words), "run", "--bundle", bundle, ...argv.slice(w.words + 1)];
  }
  return [...self, "run", "--bundle", bundle, "--", ...argv];
}
