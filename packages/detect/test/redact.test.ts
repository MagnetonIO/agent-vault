import { describe, expect, test } from "vitest";
import { createRedactor, secretForms } from "../src/index.js";
import { ALNUM, fakes } from "./fixtures/fake-keys.js";

const run = (secrets: { name: string; value: string }[], chunks: string[]): string => {
  const r = createRedactor(secrets);
  return chunks.map((c) => r.push(c)).join("") + r.flush();
};

describe("redactor", () => {
  const secret = fakes.githubPat();
  const secrets = [{ name: "gh", value: secret }];

  test("single chunk", () => {
    expect(run(secrets, [`a ${secret} b`])).toBe("a [redacted vault://gh] b");
  });

  test("secret split across two pushes (Review Focus 5)", () => {
    const r = createRedactor(secrets);
    const out = r.push(`abc${secret.slice(0, 5)}`) + r.push(`${secret.slice(5)}xyz`) + r.flush();
    expect(out).toBe("abc[redacted vault://gh]xyz");
  });

  test("split at every index 1..len-1", () => {
    for (let i = 1; i < secret.length; i++) {
      const out = run(secrets, [`pre ${secret.slice(0, i)}`, `${secret.slice(i)} post`]);
      expect(out, `split at ${i}`).toBe("pre [redacted vault://gh] post");
    }
  });

  test("one char per push", () => {
    const text = `x ${secret} y ${secret} z`;
    expect(run(secrets, [...text])).toBe("x [redacted vault://gh] y [redacted vault://gh] z");
  });

  test("secret never appears in intermediate output either", () => {
    const r = createRedactor(secrets);
    let seen = "";
    for (const ch of `x ${secret} y`) seen += r.push(ch);
    seen += r.flush();
    expect(seen).not.toContain(secret.slice(0, 10));
  });

  test("text with no secret is passed through unchanged after flush", () => {
    expect(run(secrets, ["hello ", "world"])).toBe("hello world");
  });

  describe("hold-back", () => {
    test("text that cannot start a secret is released at once (a prompt is not delayed)", () => {
      const r = createRedactor(secrets);
      expect(r.push("Password: ")).toBe("Password: ");
      expect(r.push("x".repeat(100))).toBe("x".repeat(100));
      expect(r.flush()).toBe("");
    });

    test("only the part that could still become a secret is held", () => {
      const r = createRedactor(secrets);
      expect(r.push(`Token: ${secret.slice(0, -1)}`)).toBe("Token: ");
      expect(r.push("!")).toBe(`${secret.slice(0, -1)}!`); // it was not the secret after all
      expect(r.flush()).toBe("");
    });

    test("a partial secret by itself yields nothing until it is resolved", () => {
      const r = createRedactor(secrets);
      expect(r.push(secret.slice(0, -1))).toBe("");
      expect(r.push(secret.slice(-1))).toBe("");
      expect(r.flush()).toBe("[redacted vault://gh]");
    });

    test("a prefix of an encoded form is held too", () => {
      const b64 = Buffer.from(secret).toString("base64");
      const r = createRedactor(secrets);
      expect(r.push(`k=${b64.slice(0, 10)}`)).toBe("k=");
      expect(r.push(`${b64.slice(10)}\n`)).toBe("[redacted vault://gh]\n");
      expect(r.flush()).toBe("");
    });

    test("no timer: held text stays held however long nothing arrives", async () => {
      const r = createRedactor(secrets);
      expect(r.push(secret.slice(0, 12))).toBe("");
      await new Promise((resolve) => setTimeout(resolve, 150));
      expect(r.push(secret.slice(12))).toBe("");
      expect(r.flush()).toBe("[redacted vault://gh]");
    });
  });

  test("flush empties the buffer; redactor is reusable", () => {
    const r = createRedactor(secrets);
    expect(r.push(secret.slice(0, 10)) + r.flush()).toBe(secret.slice(0, 10));
    expect(r.flush()).toBe("");
    expect(r.push(`${secret}!`) + r.flush()).toBe("[redacted vault://gh]!");
  });

  describe("encoded variants", () => {
    const value = "pa/ss+word=with spaces&odd?chars-and-more!";
    const s = [{ name: "k", value }];
    const forms = {
      raw: value,
      base64: Buffer.from(value).toString("base64"),
      base64url: Buffer.from(value).toString("base64url"),
      urlencoded: encodeURIComponent(value),
    };

    test("the forms are actually distinct", () => {
      expect(new Set(Object.values(forms)).size).toBe(4);
    });

    test.each(Object.entries(forms))("%s", (_n, form) => {
      expect(run(s, [`<${form}>`])).toBe("<[redacted vault://k]>");
      expect(run(s, [`<${form.slice(0, 7)}`, `${form.slice(7)}>`])).toBe("<[redacted vault://k]>");
    });

    test("a variant equal to the raw value is ignored (no crash, still redacts)", () => {
      expect(run([{ name: "a", value: "abcdefgh" }], ["x abcdefgh y"])).toBe(
        "x [redacted vault://a] y",
      );
    });
  });

  describe("forms a child really prints", () => {
    // A key the length of an OpenAI project key: its base64 is far longer than one wrapped line.
    const long = `sk-proj-${Array.from({ length: 100 }, (_, i) => ALNUM[(i * 7 + 3) % ALNUM.length]).join("")}`;
    const s = [{ name: "k", value: long }];
    const b64 = Buffer.from(long).toString("base64");
    const wrapped = (columns: number, lineBreak: string) =>
      (b64.match(new RegExp(`.{1,${columns}}`, "g")) as string[]).join(lineBreak);

    test("the secret is long enough that wrapping matters", () => {
      expect(long.length).toBeGreaterThan(90);
      expect(b64.length).toBeGreaterThan(76);
    });

    test.each([
      [64, "\n"],
      [64, "\r\n"],
      [76, "\n"],
      [76, "\r\n"],
    ])("base64 wrapped at %i columns with %j", (columns, lineBreak) => {
      const form = wrapped(columns, lineBreak);
      expect(form).toContain(lineBreak);
      // `base64` ends its output with a newline, which is not part of the secret.
      expect(run(s, [`${form}\n`])).toBe("[redacted vault://k]\n");
      for (let i = 1; i < form.length; i += 7) {
        expect(run(s, [form.slice(0, i), `${form.slice(i)}\n`]), `split ${i}`).toBe(
          "[redacted vault://k]\n",
        );
      }
    });

    test("lowercase %xx URL-encoding", () => {
      const value = "https://user:p@ss/word+with=odd?bytes&more#frag";
      const lower = encodeURIComponent(value).replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase());
      expect(lower).not.toBe(encodeURIComponent(value));
      expect(run([{ name: "u", value }], [`q=${lower}&x=1`])).toBe("q=[redacted vault://u]&x=1");
    });

    test("inside JSON.stringify of an environment", () => {
      const value = 'pa"ss\\word\nwith\tcontrol and "quotes"';
      const text = JSON.stringify({ PATH: "/usr/bin", TOKEN: value, HOME: "/home/u" });
      expect(text).not.toContain(value);
      expect(run([{ name: "t", value }], [text])).toBe(
        '{"PATH":"/usr/bin","TOKEN":"[redacted vault://t]","HOME":"/home/u"}',
      );
      expect(run(s, [JSON.stringify(process.env), JSON.stringify({ k: long })])).toBe(
        `${JSON.stringify(process.env)}{"k":"[redacted vault://k]"}`,
      );
    });
  });

  describe("a secret printed over and over", () => {
    const CHUNK = 16 * 1024;
    const MARKERS_ONLY = /^(\[redacted vault:\/\/k\])+$/;

    /** Push `text` in chunks; returns the output, the most ever held and the time taken. */
    const pushAll = (value: string, text: string) => {
      const r = createRedactor([{ name: "k", value }]);
      let out = "";
      let maxHeld = 0;
      const t0 = performance.now();
      for (let i = 0; i < text.length; i += CHUNK) {
        out += r.push(text.slice(i, i + CHUNK));
        maxHeld = Math.max(maxHeld, r.heldLength());
      }
      out += r.flush();
      return { out, maxHeld, ms: performance.now() - t0 };
    };

    test("1e5 back-to-back copies are linear in time and bounded in memory", () => {
      const value = "k3y-0123456789-abcdefghijklmnopqrstuvwxy"; // 40 chars
      expect(value).toHaveLength(40);
      const longest = Buffer.from(value).toString("base64").length;
      const { out, maxHeld, ms } = pushAll(value, value.repeat(100_000));
      expect(out).toMatch(MARKERS_ONLY);
      expect(maxHeld).toBeLessThanOrEqual(2 * longest);
      expect(ms).toBeLessThan(2000);
    });

    test("a secret that overlaps itself (period 2) is still only markers", () => {
      const { out, maxHeld, ms } = pushAll("abababab", "ab".repeat(200_000));
      expect(out).toMatch(MARKERS_ONLY);
      expect(maxHeld).toBeLessThanOrEqual(2 * 12);
      expect(ms).toBeLessThan(2000);
    });

    test("any chunking gives the same redaction as one push, up to marker count", () => {
      let seed = 12345;
      const rand = (n: number) => {
        seed = (Math.imul(seed, 1103515245) + 12345) >>> 0;
        return (seed >>> 8) % n;
      };
      const value = "abcabcab";
      const collapse = (text: string) => text.replace(/(\[redacted vault:\/\/k\])+/g, "M");
      for (let round = 0; round < 200; round++) {
        // Mostly the secret's own letters, so there are long overlapping runs and near misses.
        const text = Array.from({ length: 200 }, () => "abc!"[rand(round % 2 ? 4 : 3)]).join("");
        const whole = run([{ name: "k", value }], [text]);
        const pieces: string[] = [];
        for (let i = 0; i < text.length; ) {
          const n = 1 + rand(40);
          pieces.push(text.slice(i, i + n));
          i += n;
        }
        const chunked = run([{ name: "k", value }], pieces);
        expect(collapse(chunked), `round ${round}`).toBe(collapse(whole));
      }
    });
  });

  describe("multiple secrets", () => {
    test("each replaced with its own name", () => {
      const a = fakes.anthropic();
      const b = fakes.awsAkid();
      const out = run(
        [
          { name: "anthropic/key", value: a },
          { name: "aws/akid", value: b },
        ],
        [`${a} ${b}`],
      );
      expect(out).toBe("[redacted vault://anthropic/key] [redacted vault://aws/akid]");
    });

    test("same position: longest match wins", () => {
      const out = run(
        [
          { name: "short", value: "tokenvalue" },
          { name: "long", value: "tokenvalue-extended" },
        ],
        ["a tokenvalue-extended b", " tokenvalue c"],
      );
      expect(out).toBe("a [redacted vault://long] b [redacted vault://short] c");
    });

    test("longest wins when the longer one completes in a later chunk", () => {
      const out = run(
        [
          { name: "short", value: "tokenvalue" },
          { name: "long", value: "tokenvalue-extended" },
        ],
        ["a tokenvalue", "-extended b"],
      );
      expect(out).toBe("a [redacted vault://long] b");
    });
  });

  test("no secrets: pass-through with no holdback", () => {
    const r = createRedactor([]);
    expect(r.push("abc")).toBe("abc");
    expect(r.flush()).toBe("");
  });

  describe("short secrets", () => {
    test.each(["", "a", "ab", "abc"])("%j (under 4 chars) throws RangeError", (value) => {
      expect(() => createRedactor([{ name: "tiny", value }])).toThrow(RangeError);
    });

    test("the error names the secret but never shows its value", () => {
      let message = "";
      try {
        createRedactor([{ name: "my-pin", value: "s3c" }]);
      } catch (e) {
        message = (e as Error).message;
      }
      expect(message).toContain("my-pin");
      expect(message).not.toContain("s3c");
    });

    test('4 chars is allowed: "nana" in "banana" gives ba[redacted vault://x]', () => {
      expect(run([{ name: "x", value: "nana" }], ["banana"])).toBe("ba[redacted vault://x]");
    });

    test("4-7 char secrets are redacted in raw form only", () => {
      const value = "pa/s+w";
      const b64 = Buffer.from(value).toString("base64");
      expect(run([{ name: "p", value }], [`${value} ${b64}`])).toBe(`[redacted vault://p] ${b64}`);
    });

    test("8 chars gets the encoded variants", () => {
      const value = "pa/s+w=?";
      const b64 = Buffer.from(value).toString("base64");
      expect(run([{ name: "p", value }], [`<${b64}>`])).toBe("<[redacted vault://p]>");
    });
  });

  describe("overlapping and adjacent secrets", () => {
    const A = "abcd1234";
    const B = "d1234efgh5678";
    const both = [
      { name: "a", value: A },
      { name: "b", value: B },
    ];
    const text = "abcd1234efgh5678";

    const noLeak = (out: string) => {
      expect(out).not.toContain("efgh5678");
      for (let i = 0; i + 4 <= B.length; i++) expect(out).not.toContain(B.slice(i, i + 4));
    };

    test("overlap merges into ONE redaction named after the leftmost match", () => {
      const out = run(both, [text]);
      expect(out).toBe("[redacted vault://a]");
      noLeak(out);
    });

    test("same result for every split and one char per push", () => {
      for (let i = 1; i < text.length; i++) {
        expect(run(both, [text.slice(0, i), text.slice(i)]), `split ${i}`).toBe(
          "[redacted vault://a]",
        );
      }
      const out = run(both, [...`<${text}>`]);
      expect(out).toBe("<[redacted vault://a]>");
      noLeak(out);
    });

    test("the later match starting inside the hold-back window is not cut off", () => {
      // A completes (and is eligible to flush) before B is fully buffered.
      const out = run(both, ["xx abcd1234", "efgh5678 yy"]);
      expect(out).toBe("xx [redacted vault://a] yy");
    });

    test("adjacent matches merge too", () => {
      const out = run(
        [
          { name: "a", value: "aaaa1111" },
          { name: "b", value: "bbbb2222" },
        ],
        ["aaaa1111bb", "bb2222"],
      );
      expect(out).toBe("[redacted vault://a]");
    });

    test("a rightmost-named match is not used when it starts later", () => {
      const out = run(
        [
          { name: "b", value: "d1234efgh5678" },
          { name: "a", value: "abcd1234" },
        ],
        [text],
      );
      expect(out).toBe("[redacted vault://a]");
    });
  });

  test("does not split a surrogate pair at the holdback boundary", () => {
    const r = createRedactor([{ name: "n", value: "abcdefgh" }]);
    const out = r.push("\u{1F600}".repeat(20));
    expect(out).not.toMatch(/[\uD800-\uDBFF]$/);
    expect(out + r.flush()).toBe("\u{1F600}".repeat(20));
  });

  describe("custom marker and match count", () => {
    const value = "sk-live-abcdef123456";

    test("marker replaces the default text", () => {
      const r = createRedactor([{ name: "api/key", value }], { marker: (n) => `vault://${n}` });
      expect(r.push(`a ${value} b`) + r.flush()).toBe("a vault://api/key b");
    });

    test("matchCount counts redactions emitted, not matches seen", () => {
      const r = createRedactor([{ name: "k", value }]);
      expect(r.matchCount()).toBe(0);
      r.push(`x ${value} y ${value.slice(0, 6)}`);
      expect(r.matchCount()).toBe(1);
      r.push(`${value.slice(6)} z`);
      expect(r.matchCount()).toBe(2);
      r.flush();
      expect(r.matchCount()).toBe(2);
    });

    test("a held match is counted once it is flushed", () => {
      const r = createRedactor([{ name: "k", value }]);
      r.push(`end ${value}`);
      r.flush();
      expect(r.matchCount()).toBe(1);
    });

    test("the JSON-escaped form of a multi-line value matches", () => {
      const pem = "-----BEGIN KEY-----\nAAAA\nBBBB\n-----END KEY-----\n";
      const r = createRedactor([{ name: "pem", value: pem }], { marker: (n) => `vault://${n}` });
      const json = JSON.stringify({ k: pem });
      expect(r.push(json) + r.flush()).toBe('{"k":"vault://pem"}');
    });

    test("a wrapped base64 copy inside a JSON string matches (its newlines are escaped)", () => {
      const secret = "x".repeat(10) + "SeCrEt".repeat(30);
      const wrapped = Buffer.from(secret)
        .toString("base64")
        .replace(/(.{76})/g, "$1\n");
      const json = JSON.stringify({ blob: wrapped });
      const r = createRedactor([{ name: "w", value: secret }], { marker: (n) => `vault://${n}` });
      expect(r.push(json) + r.flush()).toBe('{"blob":"vault://w"}');
    });
  });

  describe("short values with JSON-special characters", () => {
    test("a short value with a quote is redacted in its escaped form too", () => {
      const r = createRedactor([{ name: "q", value: 'ab"cd' }], { marker: (n) => `<${n}>` });
      expect(r.push('{"k":"ab\\"cd","j":"ab"cd"}') + r.flush()).toBe('{"k":"<q>","j":"<q>"}');
    });

    test("secretForms lists the raw, encoded and escaped forms", () => {
      const forms = secretForms('pa"ss\\word123');
      expect(forms).toContain('pa"ss\\word123');
      expect(forms).toContain('pa\\"ss\\\\word123');
      expect(secretForms("ab")).toEqual(["ab"]);
    });
  });
});
