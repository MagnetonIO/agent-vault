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

const BEFORE_CONTEXT = 40;

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
      const refined = rule.refine
        ? rule.refine(m[0], text.slice(Math.max(0, m.index - BEFORE_CONTEXT), m.index))
        : { offset: 0, value: m[0] };
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
function pickWithinCluster(cluster: Candidate[]): Candidate[] {
  if (cluster.length === 1) return cluster;
  const ranked = [...cluster].sort(
    (a, b) => b.priority - a.priority || b.end - b.start - (a.end - a.start) || a.start - b.start,
  );
  const kept: Candidate[] = [];
  for (const c of ranked) {
    if (!kept.some((k) => c.start < k.end && k.start < c.end)) kept.push(c);
  }
  return kept;
}

/**
 * Splits candidates into clusters of transitively overlapping spans (one sweep over the
 * start-sorted list) and resolves priorities inside each cluster only. Non-overlapping
 * candidates, the common case for large inputs, never meet, so this is O(n log n).
 */
function resolveOverlaps(candidates: Candidate[]): Candidate[] {
  const byStart = [...candidates].sort((a, b) => a.start - b.start || b.end - a.end);
  const kept: Candidate[] = [];
  let cluster: Candidate[] = [];
  let clusterEnd = 0;
  const closeCluster = () => {
    for (const c of pickWithinCluster(cluster)) kept.push(c);
    cluster = [];
  };
  for (const c of byStart) {
    if (cluster.length > 0 && c.start >= clusterEnd) closeCluster();
    cluster.push(c);
    clusterEnd = Math.max(clusterEnd, c.end);
  }
  if (cluster.length > 0) closeCluster();
  return kept.sort((a, b) => a.start - b.start);
}

export function detectSecrets(text: string, opts: DetectOptions = {}): Detection[] {
  const stamp = utcStamp(opts.now ?? new Date());
  const isTaken = opts.isTaken ?? (() => false);
  const seenValues = new Set<string>();
  const nextSuffix = new Map<string, number>();
  const detections: Detection[] = [];

  for (const c of resolveOverlaps(collect(text))) {
    if (seenValues.has(c.value)) continue;
    seenValues.add(c.value);

    // Per-base counter: names handed out earlier in this call are skipped without rescanning.
    const base = `${c.namePrefix}-${stamp}`;
    let n = nextSuffix.get(base) ?? 1;
    let suggestedName = n === 1 ? base : `${base}-${n}`;
    while (isTaken(suggestedName)) suggestedName = `${base}-${++n}`;
    nextSuffix.set(base, n + 1);

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
