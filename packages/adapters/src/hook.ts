import { type Detection, detectSecrets } from "@agent-vault/detect";
import type { HarnessId } from "./adapter.js";

/**
 * The harness-independent half of Path B: a key pasted into a prompt is caught before the model
 * sees it, stored in the vault, and queued for scrubbing out of the harness's own files. Each
 * adapter turns the decision into the JSON its harness expects.
 */

/** The part of an `IpcClient` these functions use, so tests can pass a stub. */
export type HookClient = {
  call<T = unknown>(method: string, params?: unknown): Promise<T>;
  close(): void;
};

/** Tag on every key caught in a prompt: it sat in a harness file and a transcript, in plaintext. */
export const EXPOSED_TAG = "exposed-locally";

/** Shown when a key was found but could not be stored. The prompt is still blocked. */
export const HELD_BACK_REASON =
  "Key held back from the model. Run: agent-vault init, then paste again.";

/** `scrub.run` gets this long, connecting included, before the hook gives up. */
export const SCRUB_TIMEOUT_MS = 10_000;

export const storedReason = (names: string[]): string =>
  `Stored as ${names.join(", ")}. Re-send using vault://${names[0]}.`;

export type PromptDecision =
  | { block: false }
  | {
      block: true;
      reason: string;
      /** The vault names the keys were stored under; empty if storing failed or for a probe. */
      names: string[];
    };

export type PromptSubmitOptions = {
  harness: HarnessId;
  prompt: string;
  /** The harness's transcript for this session. It may not exist yet. */
  transcriptPath?: string | undefined;
  /** Other files that may hold the prompt. */
  historyFiles: string[];
  /** Connects to the daemon. Not called when the prompt holds no key. */
  client: () => Promise<HookClient>;
  /** Detection only: block with a probe reason, store nothing, never call `client`. */
  probe?: boolean | undefined;
  /** For stderr. Never gets a secret: only messages of this module and the daemon's errors. */
  log?: ((message: string) => void) | undefined;
};

const ALLOW: PromptDecision = { block: false };

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));

/**
 * Queue the files for scrubbing. `scrub.queue` refuses the whole call if one path is not under the
 * home directory, so on a refusal each file is tried alone and the bad one is dropped: a
 * transcript outside home must not keep `history.jsonl` from being queued.
 */
async function queueScrub(
  client: HookClient,
  harness: HarnessId,
  files: string[],
  secretNames: string[],
  log: (m: string) => void,
): Promise<void> {
  if (files.length === 0) return;
  try {
    await client.call("scrub.queue", { harness, files, secretNames });
    return;
  } catch (err) {
    if (files.length === 1) {
      log(`agent-vault: not queued for scrubbing: ${message(err)}`);
      return;
    }
  }
  for (const file of files) {
    try {
      await client.call("scrub.queue", { harness, files: [file], secretNames });
    } catch (err) {
      log(`agent-vault: not queued for scrubbing: ${message(err)}`);
    }
  }
}

/**
 * Decide what to do with a prompt. Detection runs here, so a prompt without a key never touches
 * the daemon. With a key: store each distinct value (`secret.put`, tagged `exposed-locally`),
 * queue the transcript and history for scrubbing, and block. Any failure after detection still
 * blocks: the key must not reach the model.
 */
export async function handlePromptSubmit(opts: PromptSubmitOptions): Promise<PromptDecision> {
  const log = opts.log ?? (() => {});
  let detections: Detection[];
  try {
    detections = detectSecrets(opts.prompt);
  } catch (err) {
    log(`agent-vault: detection failed, prompt allowed: ${message(err)}`);
    return ALLOW;
  }
  if (detections.length === 0) return ALLOW;

  if (opts.probe) {
    return {
      block: true,
      reason: `Probe: ${detections.length} key(s) detected, nothing stored.`,
      names: [],
    };
  }

  const values = [...new Set(detections.map((d) => d.value))];
  const ruleOf = new Map(detections.map((d) => [d.value, d.ruleId]));
  const names: string[] = [];
  let failed = false;
  let client: HookClient | undefined;
  try {
    client = await opts.client();
    for (const value of values) {
      try {
        const meta = await client.call<{ name: string }>("secret.put", {
          valueB64: Buffer.from(value, "utf8").toString("base64"),
          type: ruleOf.get(value),
          tags: [EXPOSED_TAG],
          harness: opts.harness,
        });
        names.push(meta.name);
      } catch (err) {
        failed = true;
        log(`agent-vault: could not store a key: ${message(err)}`);
      }
    }
    if (names.length > 0) {
      const files = [
        ...new Set([...(opts.transcriptPath ? [opts.transcriptPath] : []), ...opts.historyFiles]),
      ];
      await queueScrub(client, opts.harness, files, names, log);
    }
  } catch (err) {
    failed = true;
    log(`agent-vault: ${message(err)}`);
  } finally {
    client?.close();
  }

  if (failed || names.length === 0) return { block: true, reason: HELD_BACK_REASON, names };
  return { block: true, reason: storedReason(names), names };
}

export type ScrubOptions = {
  harness: HarnessId;
  client: () => Promise<HookClient>;
  /** Default `SCRUB_TIMEOUT_MS`. */
  timeoutMs?: number | undefined;
  log?: ((message: string) => void) | undefined;
};

/**
 * Run the scrub queue (`scrub.run`), connecting included, for at most `timeoutMs`. It never
 * throws: a session start or end must not be held up or failed by it.
 */
export async function handleScrub(opts: ScrubOptions): Promise<void> {
  const log = opts.log ?? (() => {});
  let client: HookClient | undefined;
  let timedOut = false;
  let timer: NodeJS.Timeout | undefined;
  const work = (async () => {
    const c = await opts.client();
    if (timedOut) {
      c.close();
      return;
    }
    client = c;
    await c.call("scrub.run", { harness: opts.harness });
  })();
  const limit = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      reject(new Error(`scrub did not finish in ${opts.timeoutMs ?? SCRUB_TIMEOUT_MS} ms`));
    }, opts.timeoutMs ?? SCRUB_TIMEOUT_MS);
  });
  try {
    await Promise.race([work, limit]);
  } catch (err) {
    log(`agent-vault: scrub skipped: ${message(err)}`);
  } finally {
    clearTimeout(timer);
    client?.close();
    work.catch(() => {}); // a late failure after the timeout is already logged
  }
}
