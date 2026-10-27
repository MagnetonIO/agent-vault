import { RULES } from "./rules.js";

export type Detection = {
  ruleId: string;
  value: string;
  start: number;
  end: number;
  suggestedName: string;
};

export type DetectOptions = {
  /** Reports names already in the vault so suggestions get a `-2`, `-3`, … suffix. */
  isTaken?: ((name: string) => boolean) | undefined;
  /** Date stamped into suggested names (UTC). Defaults to now. */
  now?: Date | undefined;
};

type Candidate = {
  ruleId: string;
  namePrefix: string;
  priority: number;
  value: string;
  start: number;
  end: number;
};

const utcStamp = (d: Date): string =>
  `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, "0")}${String(d.getUTCDate()).padStart(2, "0")}`;

function collect(text: string): Candidate[] {
  const out: Candidate[] = [];
  for (const rule of RULES) {
    for (const m of text.matchAll(rule.pattern)) {
      const refined = rule.refine ? rule.refine(m[0]) : { offset: 0, value: m[0] };
      if (!refined) continue;
      const start = m.index + refined.offset;
      out.push({
        ruleId: rule.id,
        namePrefix: rule.namePrefix,
        priority: rule.priority,
        value: refined.value,
        start,
        end: start + refined.value.length,
      });
    }
  }
  return out;
}

/** Most specific rule first, then the longer span, then the earlier one; skip anything overlapping. */
function resolveOverlaps(candidates: Candidate[]): Candidate[] {
  const ranked = [...candidates].sort(
    (a, b) => b.priority - a.priority || b.end - b.start - (a.end - a.start) || a.start - b.start,
  );
  const kept: Candidate[] = [];
  for (const c of ranked) {
    if (!kept.some((k) => c.start < k.end && k.start < c.end)) kept.push(c);
  }
  return kept.sort((a, b) => a.start - b.start);
}

export function detectSecrets(text: string, opts: DetectOptions = {}): Detection[] {
  const stamp = utcStamp(opts.now ?? new Date());
  const isTaken = opts.isTaken ?? (() => false);
  const seenValues = new Set<string>();
  const handedOut = new Set<string>();
  const detections: Detection[] = [];

  for (const c of resolveOverlaps(collect(text))) {
    if (seenValues.has(c.value)) continue;
    seenValues.add(c.value);

    const base = `${c.namePrefix}-${stamp}`;
    let suggestedName = base;
    for (let n = 2; handedOut.has(suggestedName) || isTaken(suggestedName); n++) {
      suggestedName = `${base}-${n}`;
    }
    handedOut.add(suggestedName);

    detections.push({
      ruleId: c.ruleId,
      value: c.value,
      start: c.start,
      end: c.end,
      suggestedName,
    });
  }
  return detections;
}
