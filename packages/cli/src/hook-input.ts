import { detectSecrets } from "@agent-vault/detect";

/**
 * Reading a hook's stdin, and the fast path for `hook <harness> prompt-submit`: most prompts hold
 * no key, so they are answered here, before the rest of the CLI (commander, the daemon client, the
 * adapters) is loaded. This module must import nothing heavy.
 */

/** A prompt larger than this is not read: nobody pastes a key into 8 MiB. */
export const STDIN_CAP_BYTES = 8 * 1024 * 1024;

export type HookInput = { oversize: true } | { oversize: false; raw: string };

type Source = AsyncIterable<Buffer | string> & { isTTY?: boolean };

/**
 * All of `stream` as text, or `oversize` if it holds more than `cap` bytes. The rest of an
 * oversize stream is read and dropped so the harness is never left writing into a closed pipe.
 */
export async function readCapped(stream: Source, cap = STDIN_CAP_BYTES): Promise<HookInput> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size <= cap) chunks.push(typeof chunk === "string" ? Buffer.from(chunk) : chunk);
    else chunks.length = 0;
  }
  return size > cap
    ? { oversize: true }
    : { oversize: false, raw: Buffer.concat(chunks).toString("utf8") };
}

let taken: Promise<HookInput> | undefined;

/** The hook's input. Read once: the fast path and the full command share the result. */
export function readHookInput(stream: Source): Promise<HookInput> {
  taken ??= readCapped(stream);
  return taken;
}

/**
 * True when argv is `hook <harness> prompt-submit` and the prompt holds no key, so the answer is
 * "allow" (print nothing, exit 0). False in every other case, including any doubt: the full
 * command then decides, and blocks a prompt whose detection throws. Never throws.
 */
export async function fastAllow(
  argv: string[],
  stdin: Source,
  detect: (text: string) => unknown[] = detectSecrets,
): Promise<boolean> {
  try {
    if (argv[2] !== "hook" || argv[4] !== "prompt-submit" || stdin.isTTY) return false;
    const input = await readHookInput(stdin);
    if (input.oversize) return false;
    const parsed: unknown = JSON.parse(input.raw);
    const prompt = (parsed as { prompt?: unknown } | null)?.prompt;
    return typeof prompt === "string" && detect(prompt).length === 0;
  } catch {
    return false;
  }
}
