import { describe, expect, test } from "vitest";
import { registry } from "../src/methods/index.js";
import { b64, MODES, useDaemon } from "./helpers.js";

const SECRET = "registry-test-secret-éü-7788";

/** Valid params for every non-mutating method. A new method without an entry fails the test. */
const READ_PARAMS: Record<string, unknown> = {
  status: undefined,
  "secret.list": undefined,
  "bundle.list": undefined,
  "audit.query": { limit: 50 },
  "audit.verify": undefined,
};

/** Every encoding of `value` that a leak could take. */
function forms(value: string): string[] {
  const raw = Buffer.from(value, "utf8");
  const b64s = raw.toString("base64");
  return [
    value,
    b64s,
    b64s.replace(/=+$/, ""),
    raw.toString("base64url"),
    raw.toString("hex"),
    raw.toString("hex").toUpperCase(),
  ];
}

describe("method registry", () => {
  test("no method returns secret bytes", () => {
    const leaking = Object.entries(registry)
      .filter(([, def]) => def.returnsSecret)
      .map(([name]) => name);
    expect(leaking).toEqual([]);
    // helper.get (Task 12) is the one method allowed to; it is not registered yet.
    expect(registry["helper.get"]).toBeUndefined();
  });

  test("the registry is frozen and every entry is complete", () => {
    expect(Object.isFrozen(registry)).toBe(true);
    for (const def of Object.values(registry)) {
      expect(typeof def.handler).toBe("function");
      expect(typeof def.mutates).toBe("boolean");
      expect(typeof def.returnsSecret).toBe("boolean");
    }
  });

  test("the sample params cover every non-mutating method", () => {
    const reads = Object.entries(registry)
      .filter(([, def]) => !def.mutates)
      .map(([name]) => name)
      .sort();
    expect(Object.keys(READ_PARAMS).sort()).toEqual(reads);
  });

  describe.each(MODES)("over %s", (mode) => {
    const env = useDaemon(mode, { init: true });

    test("no registered read returns the stored value in any encoding", async () => {
      const put = await env.client.call("secret.put", {
        name: "leak/check",
        valueB64: b64(SECRET),
        tags: ["t"],
      });
      await env.client.call("bundle.create", { name: "leak-bundle" });
      await env.client.call("bundle.grant", {
        bundle: "leak-bundle",
        env: "LEAK",
        secret: "leak/check",
      });

      const responses: unknown[] = [put];
      for (const [method, def] of Object.entries(registry)) {
        if (def.mutates) continue;
        responses.push(await env.client.call(method, READ_PARAMS[method]));
      }
      const wire = JSON.stringify(responses);
      for (const form of forms(SECRET)) expect(wire).not.toContain(form);
      expect(wire).toContain("leak/check");
    });
  });
});
