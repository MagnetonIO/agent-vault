import { createHash } from "node:crypto";

// Generated fakes only. Bodies come from a seeded PRNG and every key is assembled from
// parts at runtime so no literal key-shaped string exists in the repo.

const range = (from: string, to: string) =>
  String.fromCharCode(
    ...Array.from(
      { length: to.charCodeAt(0) - from.charCodeAt(0) + 1 },
      (_, i) => from.charCodeAt(0) + i,
    ),
  );
const UPPER = range("A", "Z");
const DIGITS = range("0", "9");
export const ALNUM = `${UPPER}${range("a", "z")}${DIGITS}`;
const UPPER_DIGITS = `${UPPER}${DIGITS}`;
const URLSAFE = `${ALNUM}_-`;
export const B64 = `${ALNUM}+/`;

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Deterministic string of `n` chars drawn from `alphabet`. */
export function body(alphabet: string, n: number, seed: number): string {
  const rnd = mulberry32(seed);
  let out = "";
  for (let i = 0; i < n; i++) out += alphabet[Math.floor(rnd() * alphabet.length)];
  return out;
}

const b64url = (s: string) => Buffer.from(s, "utf8").toString("base64url");

export const fakes = {
  anthropic: () => `sk-${"ant"}-${body(URLSAFE, 48, 1)}`,
  anthropic2: () => `sk-${"ant"}-${body(URLSAFE, 48, 11)}`,
  openai: () => `sk-${body(ALNUM, 48, 2)}`,
  openaiProj: () => `sk-${"proj"}-${body(URLSAFE, 60, 3)}`,
  githubPat: () => `gh${"p"}_${body(ALNUM, 36, 4)}`,
  githubFine: () => `github${"_pat"}_${body(`${ALNUM}_`, 70, 5)}`,
  slack: () => `xo${"xb"}-${body(`${ALNUM}-`, 40, 6)}`,
  awsAkid: () => `AK${"IA"}${body(UPPER_DIGITS, 16, 7)}`,
  apify: () => `apify${"_api"}_${body(ALNUM, 30, 8)}`,
  jwt: () =>
    [
      b64url('{"alg":"HS256","typ":"JWT"}'),
      b64url('{"sub":"fake-subject","name":"Fake User","iat":1700000000}'),
      body(URLSAFE, 43, 9),
    ].join("."),
  pem: () =>
    [
      `-----BEGIN ${"RSA "}PRIVATE KEY-----`,
      body(B64, 64, 10),
      body(B64, 64, 20),
      body(B64, 24, 30),
      `-----END ${"RSA "}PRIVATE KEY-----`,
    ].join("\n"),
  generic: () => body(B64, 40, 12),
  genericMixed: () => body(`${ALNUM}+/=_-`, 40, 77),
};

export const benign = {
  camel: "someVeryLongCamelCaseIdentifierNameWithNumbers123AndMoreStuff",
  srcPath: "src/components/UserProfileSettingsPanel/index2/hooks-useThing",
  branch: "feature/AGENT-1234-add-detect-package-with-long-branch-name",
  lockfileIntegrity: `sha${"512"}-${body(B64, 86, 41)}==`,
  dataUri: `data:image/png;base64,${body(B64, 120, 42)}==`,
  gitSha: createHash("sha1").update("test").digest("hex"),
  sha256: createHash("sha256").update("").digest("hex"),
  uuid: "123e4567-e89b-12d3-a456-426614174000",
  npm: "npm install --save-dev vitest typescript",
  path: "/Users/someone/Documents/Development/project/packages/detect/src/index.ts",
  task: "run the task-runner-configuration-for-everything now",
};
