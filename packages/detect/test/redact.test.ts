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

  test("empty secret value is ignored", () => {
    expect(run([{ name: "e", value: "" }], ["abc"])).toBe("abc");
  });

  test("does not split a surrogate pair at the holdback boundary", () => {
    const r = createRedactor([{ name: "n", value: "abcdefgh" }]);
    const out = r.push("\u{1F600}".repeat(20));
    expect(out).not.toMatch(/[\uD800-\uDBFF]$/);
    expect(out + r.flush()).toBe("\u{1F600}".repeat(20));
  });
});
