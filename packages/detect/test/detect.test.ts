import { describe, expect, test } from "vitest";
import { createRedactor, type Detection, detectSecrets, fingerprint } from "../src/index.js";
import { ALNUM, B64, benign, body, fakes } from "./fixtures/fake-keys.js";

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

  test("pem truncated mid-body is still detected, BEGIN line through last body line", () => {
    const full = fakes.pem().split("\n");
    const truncated = full.slice(0, 3).join("\n");
    const text = `here is my key:\n${truncated}`;
    const d = one(text);
    expect(d.ruleId).toBe("pem");
    expect(d.value).toBe(truncated);
    expect(text.slice(d.start, d.end)).toBe(truncated);
  });

  test("pem BEGIN line followed by prose: span ends before the prose", () => {
    const lines = fakes.pem().split("\n");
    const key = lines.slice(0, 2).join("\n");
    const text = `${key}\nOops, that got cut off. Can you still help?`;
    const d = one(text);
    expect(d.ruleId).toBe("pem");
    expect(text.slice(d.start, d.end)).toBe(key);
    expect(d.value).not.toContain("Oops");
  });

  test("pem truncated at a blank line stops there; Proc-Type headers are included", () => {
    const lines = fakes.pem().split("\n");
    const key = [lines[0], "Proc-Type: 4,ENCRYPTED", "DEK-Info: AES-128-CBC,00", lines[1]].join(
      "\n",
    );
    const text = `${key}\n\n${lines[2]}`;
    const pem = detectSecrets(text, { now: NOW }).find((x) => x.ruleId === "pem");
    expect(pem && text.slice(pem.start, pem.end)).toBe(key);
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

describe("pem in JSON (GCP service-account style)", () => {
  const pemLines = () => fakes.pem().split("\n");

  test.each([
    ["\\n", "\\n escapes"],
    ["\\r\\n", "\\r\\n escapes"],
  ])(
    "literal %s is a line separator: one detection BEGIN..END, 0 body chars after redaction",
    (sep) => {
      const pem = pemLines().join(sep);
      const text = `{"type":"service_account","private_key":"${pem}${sep}","client_email":"x@example.test"}`;
      const found = detectSecrets(text, { now: NOW });
      expect(found).toHaveLength(1);
      const d = found[0] as Detection;
      expect(d.ruleId).toBe("pem");
      expect(d.value).toBe(pem);
      expect(text.slice(d.start, d.end)).toBe(pem);

      const r = createRedactor(found.map((x) => ({ name: x.suggestedName, value: x.value })));
      const out = r.push(text) + r.flush();
      for (const line of pemLines().slice(1, -1)) expect(out).not.toContain(line.slice(0, 12));
      expect(out).toMatch(/^\{"type":"service_account","private_key":"\[redacted vault:\/\/pem\//);
      expect(out).toContain('","client_email":"x@example.test"}');
    },
  );

  test("JSON.stringify output of a PEM value is fully covered by one detection", () => {
    const text = JSON.stringify({ private_key: `${fakes.pem()}\n`, id: "1" });
    const found = detectSecrets(text, { now: NOW });
    expect(found.map((d) => d.ruleId)).toEqual(["pem"]);
    const d = found[0] as Detection;
    expect(d.value.startsWith("-----BEGIN RSA PRIVATE KEY-----")).toBe(true);
    expect(d.value.endsWith("-----END RSA PRIVATE KEY-----")).toBe(true);
  });
});

describe("generic-high-entropy false positives", () => {
  test.each([
    ["camelCase identifier", benign.camel],
    ["source path", benign.srcPath],
    ["branch name", benign.branch],
    ["lockfile integrity hash", benign.lockfileIntegrity],
    ["data URI payload", benign.dataUri],
  ])("%s yields 0 detections", (_n, text) => {
    expect(detectSecrets(text)).toEqual([]);
    expect(detectSecrets(`ref: ${text} (see above)`)).toEqual([]);
  });

  test("integrity hash after an assignment name is still ignored", () => {
    expect(detectSecrets(`integrity=${benign.lockfileIntegrity}`)).toEqual([]);
  });

  test("a random 40-char string over [A-Za-z0-9+/=_-] is detected whole", () => {
    const v = fakes.genericMixed();
    const d = one(`secret: ${v}`);
    expect(d.ruleId).toBe("generic-high-entropy");
    expect(d.value).toBe(v);
  });

  test("random 40-char strings are detected (>= 99% of 300 seeds)", () => {
    let hits = 0;
    for (let seed = 1000; seed < 1300; seed++) {
      const v = body(`${B64}=_-`, 40, seed);
      if (detectSecrets(` ${v} `).some((d) => d.value === v)) hits++;
    }
    expect(hits).toBeGreaterThanOrEqual(297);
  });

  test("an interior = in a random string does not split it", () => {
    const v = `${body(B64, 18, 5)}=${body(B64, 21, 6)}`;
    expect(one(`x ${v} y`).value).toBe(v);
  });
});

describe("performance", () => {
  test("1 MB of 64-column random base64 lines scans in under 1000 ms", () => {
    const flat = body(B64, 1024 * 1024, 99);
    const lines: string[] = [];
    for (let i = 0; i < flat.length; i += 64) lines.push(flat.slice(i, i + 64));
    const text = lines.join("\n");

    const t0 = performance.now();
    const found = detectSecrets(text, { now: NOW });
    const ms = performance.now() - t0;

    expect(found.length).toBeGreaterThan(10_000);
    expect(ms).toBeLessThan(1000);
    // names stay unique without rescanning
    expect(new Set(found.map((d) => d.suggestedName)).size).toBe(found.length);
  });
});

describe("single runs of several MiB (V8 throws RangeError on a regex repeat that long)", () => {
  const MiB = 1024 * 1024;
  const BLOCK = 64 * 1024;
  /** `size` chars from `alphabet`: one random 64 KiB block repeated, so building it is fast. */
  const run = (alphabet: string, size: number, seed: number): string =>
    body(alphabet, BLOCK, seed)
      .repeat(Math.ceil(size / BLOCK))
      .slice(0, size);
  const URLSAFE = `${ALNUM}_-`;
  // Prefixes are assembled at runtime, like the fakes, so no key-shaped literal is in the repo.
  const cases: [rule: string, build: (size: number) => string][] = [
    ["generic-high-entropy", (n) => run(B64, n, 1)],
    ["anthropic", (n) => `sk-${"ant"}-${run(URLSAFE, n, 2)}`],
    ["openai", (n) => `sk-${run(URLSAFE, n, 3)}`],
    ["github", (n) => `github${"_pat"}_${run(`${ALNUM}_`, n, 4)}`],
    ["slack", (n) => `xo${"xb"}-${run(`${ALNUM}-`, n, 5)}`],
    ["apify", (n) => `apify${"_api"}_${run(ALNUM, n, 6)}`],
    ["jwt", (n) => `eyJ${run(URLSAFE, n, 7)}.eyJ${body(URLSAFE, 40, 8)}.${body(URLSAFE, 40, 9)}`],
    ["pem", (n) => `-----BEGIN ${"RSA "}PRIVATE KEY-----\n${run(B64, n, 10)}`],
  ];

  test.each(cases)("%s: a 9 MiB run is one detection, spanning the whole run", (rule, build) => {
    // Line breaks around it: a PEM body line only counts when a line break ends it.
    const text = `before\n${build(9 * MiB)}\n(after)`;
    const found = detectSecrets(text, { now: NOW });
    expect(found.map((d) => d.ruleId)).toEqual([rule]);
    const [d] = found as [Detection];
    expect(d.start).toBe("before\n".length);
    expect(d.end).toBe(text.length - "\n(after)".length);
  });

  test.each(cases)("%s: an 8 MiB run scans in under 2 s", (_rule, build) => {
    const text = build(8 * MiB);
    const t0 = performance.now();
    detectSecrets(text, { now: NOW });
    expect(performance.now() - t0).toBeLessThan(2000);
  });

  test("a key next to a 9 MiB blob is still found", () => {
    const key = fakes.anthropic();
    const found = detectSecrets(`${key} ${run(B64, 9 * MiB, 11)}`, { now: NOW });
    expect(found.map((d) => d.value)).toContain(key);
  });

  test("runs that never match (padding, letters, a header with no end) stay fast", () => {
    for (const text of [
      `${"=".repeat(9 * MiB)}A`,
      `${"a".repeat(9 * MiB)}1`,
      `${"A".repeat(9 * MiB)}1`,
      `-----BEGIN ${"A".repeat(9 * MiB)}`,
      "-eyJ".repeat((9 * MiB) / 4),
    ]) {
      const t0 = performance.now();
      expect(detectSecrets(text, { now: NOW })).toEqual([]);
      expect(performance.now() - t0).toBeLessThan(2000);
    }
  });

  test("an ENV_NAME longer than any real one still splits off the value", () => {
    const value = body(B64, 40, 12);
    const found = detectSecrets(`API${"_X".repeat(100_000)}=${value}`, { now: NOW });
    expect(found.map((d) => d.value)).toEqual([value]);
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
