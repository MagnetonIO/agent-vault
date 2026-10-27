import { createRedactor, secretForms } from "@agent-vault/detect";

export const REF_PREFIX = "vault://";

/** Thrown when replacing a secret would leave a JSON line that no longer parses. */
export class JsonCorruptionError extends Error {
  constructor() {
    super("would corrupt JSON");
    this.name = "JsonCorruptionError";
  }
}

/** A line of a JSON Lines file: an object or an array after any leading whitespace. */
const JSON_LIKE = /^\s*[{[]/;

const escapeJson = (text: string): string => JSON.stringify(text).slice(1, -1);

export type BlockScrubber = {
  /** `block` (whole lines) with every secret replaced. Untouched lines come back byte-identical. */
  scrubBlock(block: string): string;
  /**
   * Where to cut `text` (which ends in `cut`, a line start) so the lines before it can be
   * scrubbed now: earlier than `cut` if the last lines could be the start of a multi-line secret.
   */
  holdFrom(text: string, cut: number): number;
  /** How many replacements have been made so far. */
  matchCount(): number;
};

/**
 * The text side of the scrubber. A line that is JSON is scrubbed by its string values: the
 * value is decoded, the secrets replaced in the decoded text, and only that one string token is
 * written back, so structure, keys, numbers and spacing are never touched and a replacement
 * cannot break the line. Any other text (and a line that only looks like JSON) is redacted as
 * plain text, a run of lines at a time so a multi-line secret still matches.
 */
export function createBlockScrubber(secrets: { name: string; value: string }[]): BlockScrubber {
  const redactor = createRedactor(secrets, { marker: (name) => `${REF_PREFIX}${name}` });
  const forms = [...new Set(secrets.flatMap((s) => secretForms(s.value)))];
  // A secret that sits in a JSON string shows up in the line in any of its forms, and in each
  // form escaped once more (a transcript of a file that holds JSON).
  const needles = [...new Set(forms.flatMap((form) => [form, escapeJson(form)]))];
  const multiLine = forms.filter((form) => form.includes("\n"));
  const longestMulti = Math.max(0, ...multiLine.map((form) => form.length));

  const hasNeedle = (text: string): boolean => needles.some((needle) => text.includes(needle));
  const redactText = (text: string): string => redactor.push(text) + redactor.flush();

  /** `core` is a JSON text that parses. Replace secrets in its string values only. */
  function scrubJsonText(core: string): string {
    let out = "";
    let copied = 0;
    for (let start = core.indexOf('"'); start !== -1; start = core.indexOf('"', start)) {
      let end = start + 1;
      while (end < core.length && core[end] !== '"') end += core[end] === "\\" ? 2 : 1;
      let after = end + 1;
      while (" \t\r\n".includes(core[after] ?? "x")) after++;
      const isKey = core[after] === ":";
      const token = core.slice(start, end + 1);
      if (!isKey && hasNeedle(token)) {
        const text = JSON.parse(token) as string;
        const redacted = redactText(text);
        if (redacted !== text) {
          out += core.slice(copied, start) + JSON.stringify(redacted);
          copied = end + 1;
        }
      }
      start = end + 1;
    }
    return out + core.slice(copied);
  }

  function scrubJsonLine(line: string): string {
    const core = line.trim();
    const lead = line.slice(0, line.length - line.trimStart().length);
    const trail = line.slice(line.trimEnd().length);
    try {
      JSON.parse(core);
    } catch {
      return redactText(line);
    }
    const scrubbed = scrubJsonText(core);
    if (scrubbed === core) return line;
    try {
      JSON.parse(scrubbed);
    } catch {
      throw new JsonCorruptionError();
    }
    return lead + scrubbed + trail;
  }

  return {
    scrubBlock(block) {
      if (!hasNeedle(block)) return block;
      let out = "";
      let run = ""; // consecutive plain-text lines, redacted together
      for (let pos = 0; pos < block.length; ) {
        const nl = block.indexOf("\n", pos);
        const end = nl === -1 ? block.length : nl + 1;
        const line = block.slice(pos, end);
        pos = end;
        if (!JSON_LIKE.test(line)) {
          run += line;
          continue;
        }
        if (run !== "") {
          out += redactText(run);
          run = "";
        }
        out += hasNeedle(line) ? scrubJsonLine(line) : line;
      }
      return run === "" ? out : out + redactText(run);
    },

    holdFrom(text, cut) {
      if (longestMulti === 0) return cut;
      let hold = cut;
      // `cut` is a line start; look at every line start within one secret's length before it.
      for (let i = cut - 2; i >= Math.max(-1, cut - longestMulti); i--) {
        if (i !== -1 && text[i] !== "\n") continue;
        const tail = text.slice(i + 1);
        if (multiLine.some((form) => form.length > tail.length && form.startsWith(tail))) {
          hold = i + 1;
        }
      }
      return hold;
    },

    matchCount: () => redactor.matchCount(),
  };
}
