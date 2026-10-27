import { describe, expect, test } from "vitest";
import { createRedactor } from "../src/index.js";
import { fakes } from "./fixtures/fake-keys.js";

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

  test("push holds back at most maxVariantLength - 1 chars", () => {
    const r = createRedactor([{ name: "n", value: "SECRETVALUE" }]);
    const longest = Math.max(
      "SECRETVALUE".length,
      Buffer.from("SECRETVALUE").toString("base64").length,
    );
    const out = r.push("x".repeat(100));
    expect(out.length).toBe(100 - (longest - 1));
    expect(out + r.flush()).toBe("x".repeat(100));
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
});
