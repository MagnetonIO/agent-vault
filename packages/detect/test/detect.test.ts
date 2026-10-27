import { describe, expect, test } from "vitest";
import { type Detection, detectSecrets, fingerprint } from "../src/index.js";
import { benign, fakes } from "./fixtures/fake-keys.js";

const NOW = new Date(Date.UTC(2026, 9, 27, 23, 59, 0));

const one = (text: string): Detection => {
  const found = detectSecrets(text, { now: NOW });
  expect(found).toHaveLength(1);
  return found[0] as Detection;
};

describe("rules", () => {
  const cases: [string, () => string, string, string][] = [
    ["anthropic", fakes.anthropic, "anthropic", "anthropic/api-key"],
    ["openai", fakes.openai, "openai", "openai/api-key"],
    ["openai (proj)", fakes.openaiProj, "openai", "openai/api-key"],
    ["github pat", fakes.githubPat, "github", "github/pat"],
    ["github fine-grained", fakes.githubFine, "github", "github/pat"],
    ["slack", fakes.slack, "slack", "slack/token"],
    ["aws-akid", fakes.awsAkid, "aws-akid", "aws/access-key-id"],
    ["apify", fakes.apify, "apify", "apify/api-token"],
    ["jwt", fakes.jwt, "jwt", "jwt/token"],
    ["pem", fakes.pem, "pem", "pem/private-key"],
    ["generic-high-entropy", fakes.generic, "generic-high-entropy", "secret/unnamed"],
  ];

  test.each(cases)("%s is detected with exact span and name", (_label, make, ruleId, prefix) => {
    const value = make();
    const text = `before ${value} after`;
    const d = one(text);
    expect(d.ruleId).toBe(ruleId);
    expect(d.value).toBe(value);
    expect(text.slice(d.start, d.end)).toBe(value);
    expect(d.suggestedName).toBe(`${prefix}-20261027`);
  });

  test("github rule accepts all of ghp/gho/ghu/ghs/ghr", () => {
    for (const k of ["p", "o", "u", "s", "r"]) {
      const v = fakes.githubPat().replace("ghp_", `gh${k}_`);
      expect(one(`x ${v} y`).ruleId).toBe("github");
    }
  });

  test("slack rule accepts xoxa/b/p/r/s", () => {
    for (const k of ["a", "b", "p", "r", "s"]) {
      const v = fakes.slack().replace("xoxb-", `xox${k}-`);
      expect(one(`x ${v} y`).ruleId).toBe("slack");
    }
  });

  test("a github token longer than 36 chars is redacted whole (generic fallback), not as a prefix", () => {
    const v = `${fakes.githubPat()}Zq81`;
    const d = one(`t ${v} t`);
    expect(d.value).toBe(v);
    expect(d.ruleId).toBe("generic-high-entropy");
  });

  test("anthropic keys are not also reported as openai", () => {
    expect(one(fakes.anthropic()).ruleId).toBe("anthropic");
  });

  test("KEY=value: specific rule wins over the wider generic match", () => {
    const v = fakes.githubPat();
    const text = `GITHUB_TOKEN=${v}`;
    const d = one(text);
    expect(d.ruleId).toBe("github");
    expect(text.slice(d.start, d.end)).toBe(v);
  });

  test("generic: assignment name is not part of the value", () => {
    const v = fakes.generic();
    const text = `MY_SECRET=${v}`;
    const d = one(text);
    expect(d.ruleId).toBe("generic-high-entropy");
    expect(d.value).toBe(v);
    expect(text.slice(d.start, d.end)).toBe(v);
  });

  test("jwt is one detection, not jwt plus generic segments", () => {
    const d = one(`Authorization: Bearer ${fakes.jwt()}`);
    expect(d.ruleId).toBe("jwt");
  });

  test("pem body does not produce extra generic detections", () => {
    const d = one(`key:\n${fakes.pem()}\nend`);
    expect(d.ruleId).toBe("pem");
    expect(d.value).toBe(fakes.pem());
  });

  test("a sk- inside a longer word is not an openai key", () => {
    expect(detectSecrets("task-abcdefghijklmnopqrstuvwxyz is not a key")).toEqual([]);
  });
});

describe("boundaries (Review Focus 2)", () => {
  test("PAT in backticks + quoted sk-ant + AKIA before a comma = 3 detections", () => {
    const pat = fakes.githubPat();
    const ant = fakes.anthropic();
    const akid = fakes.awsAkid();
    const text = `Use \`${pat}\` for git, "${ant}" for the model, and ${akid}, thanks.`;
    const found = detectSecrets(text, { now: NOW });
    expect(found).toHaveLength(3);
    expect(found.map((d) => d.ruleId)).toEqual(["github", "anthropic", "aws-akid"]);
    for (const [d, v] of [
      [found[0], pat],
      [found[1], ant],
      [found[2], akid],
    ] as const) {
      expect(d?.value).toBe(v);
      expect(text.slice(d?.start, d?.end)).toBe(v);
    }
  });

  test("results are sorted by start", () => {
    const a = fakes.anthropic();
    const b = fakes.githubPat();
    const found = detectSecrets(`${b} ${a}`);
    expect(found.map((d) => d.start)).toEqual([...found.map((d) => d.start)].sort((x, y) => x - y));
  });

  test.each([",", ".", ")", '"', "'", "`", ";", "]"])(
    "trailing %s is not part of the match",
    (p) => {
      const v = fakes.githubPat();
      const text = `(${v}${p} next`;
      const d = one(text);
      expect(d.value).toBe(v);
      expect(text.slice(d.start, d.end)).toBe(v);
    },
  );

  test("fenced code block", () => {
    const v = fakes.openai();
    const text = `\`\`\`sh\nexport OPENAI_API_KEY=${v}\n\`\`\``;
    const d = one(text);
    expect(d.value).toBe(v);
  });
});

describe("overlaps and dedup", () => {
  test("same value twice yields one detection (first occurrence)", () => {
    const v = fakes.anthropic();
    const text = `${v} and again ${v}`;
    const d = one(text);
    expect(d.start).toBe(0);
  });

  test("generic never duplicates a span a specific rule already took", () => {
    const found = detectSecrets(`${fakes.slack()} ${fakes.apify()} ${fakes.openaiProj()}`);
    expect(found.map((d) => d.ruleId)).toEqual(["slack", "apify", "openai"]);
    const spans = found.map((d) => `${d.start}:${d.end}`);
    expect(new Set(spans).size).toBe(spans.length);
  });
});

describe("no false positives", () => {
  test.each(Object.entries(benign))("%s", (_k, text) => {
    expect(detectSecrets(`see ${text} ok`)).toEqual([]);
  });

  test("hex of any length is not generic-high-entropy", () => {
    for (const n of [32, 40, 64, 128]) {
      expect(detectSecrets(`h=${"0123456789abcdef".repeat(10).slice(0, n)}`)).toEqual([]);
    }
  });

  test("plain prose and low-entropy long runs", () => {
    expect(detectSecrets("please run npm install and then pnpm test")).toEqual([]);
    expect(detectSecrets("a".repeat(64))).toEqual([]);
    expect(detectSecrets("")).toEqual([]);
  });
});

describe("suggestedName", () => {
  test("uses opts.now as a UTC date", () => {
    expect(one(fakes.apify()).suggestedName).toMatch(/^apify\/api-token-\d{8}$/);
    const d = detectSecrets(fakes.apify(), { now: new Date(Date.UTC(2027, 0, 5, 0, 0, 0)) })[0];
    expect(d?.suggestedName).toBe("apify/api-token-20270105");
  });

  test("two keys of one kind in one call get -yyyymmdd and -yyyymmdd-2", () => {
    const text = `${fakes.anthropic()} ${fakes.anthropic2()}`;
    const found = detectSecrets(text, { now: NOW });
    expect(found.map((d) => d.suggestedName)).toEqual([
      "anthropic/api-key-20261027",
      "anthropic/api-key-20261027-2",
    ]);
  });

  test("isTaken pushes the suffix on: -2 then -3", () => {
    const taken = new Set(["anthropic/api-key-20261027", "anthropic/api-key-20261027-2"]);
    const d = detectSecrets(fakes.anthropic(), { now: NOW, isTaken: (n) => taken.has(n) })[0];
    expect(d?.suggestedName).toBe("anthropic/api-key-20261027-3");
  });

  test("names satisfy the vault name grammar", () => {
    for (const make of Object.values(fakes)) {
      const d = detectSecrets(make(), { now: NOW })[0];
      expect(d?.suggestedName).toMatch(/^[a-z0-9][a-z0-9._-]*(\/[a-z0-9][a-z0-9._-]*)*$/);
    }
  });
});

describe("fingerprint", () => {
  test("format is '<ruleId> len=<N> sha256:<8 hex>' and never contains the value", () => {
    const d = one(fakes.githubPat());
    const fp = fingerprint(d);
    expect(fp).toMatch(/^github len=40 sha256:[0-9a-f]{8}$/);
    expect(fp).not.toContain(d.value);
    expect(fp).not.toContain(d.value.slice(0, 8));
  });

  test("known vector: sha256('abc') starts ba7816bf", () => {
    expect(fingerprint({ ruleId: "x", value: "abc" })).toBe("x len=3 sha256:ba7816bf");
  });

  test("is deterministic and value-sensitive", () => {
    const a = fingerprint({ ruleId: "r", value: "one-value" });
    expect(fingerprint({ ruleId: "r", value: "one-value" })).toBe(a);
    expect(fingerprint({ ruleId: "r", value: "two-value" })).not.toBe(a);
  });
});
