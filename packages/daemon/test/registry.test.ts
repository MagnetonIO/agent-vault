import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import type { RpcError } from "../src/errors.js";
import { registry } from "../src/methods/index.js";
import { b64, MODES, useDaemon } from "./helpers.js";

const SECRET = "registry-test-secret-éü-7788";

/**
 * Methods that are not `mutates` but write their own audit events (`run.*` is covered in
 * runner.test.ts, `daemon.stop` in lifecycle.test.ts; calling it here would stop the daemon).
 */
const SELF_AUDITED = new Set(["run.start", "run.stdin", "run.signal", "daemon.stop"]);

/** Valid params for every other non-mutating method. A new method without an entry fails the test. */
const READ_PARAMS: Record<string, unknown> = {
  status: undefined,
  "secret.list": undefined,
  "bundle.list": undefined,
  "audit.query": { limit: 50 },
  "audit.verify": undefined,
  "capture.begin": {},
  "capture.wait": { elicitationId: "00000000-0000-4000-8000-000000000000", timeoutMs: 1 },
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

/** POST the capture form like the page does and return the whole HTTP response as text. */
function submit(url: string, value: string): Promise<string> {
  const u = new URL(url);
  const body = new URLSearchParams({ name: "leak/browser", value }).toString();
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port: u.port,
        path: u.pathname,
        method: "POST",
        agent: false,
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "content-length": Buffer.byteLength(body),
          origin: u.origin,
        },
      },
      (res) => {
        const parts: string[] = [JSON.stringify(res.headers)];
        res.setEncoding("utf8");
        res.on("data", (c: string) => parts.push(c));
        res.on("end", () => resolve(parts.join("")));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

describe("method registry", () => {
  test("only helper.get and vault.init return secret bytes", () => {
    const leaking = Object.entries(registry)
      .filter(([, def]) => def.returnsSecret)
      .map(([name]) => name);
    // helper.get serves only secrets tagged `helper`. vault.init returns the 24 recovery words
    // once, at init; they unlock the whole vault. Nothing else may ever join this set.
    expect(new Set(leaking)).toEqual(new Set(["helper.get", "vault.init"]));
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
      .filter(([name, def]) => !def.mutates && !SELF_AUDITED.has(name))
      .map(([name]) => name)
      .sort();
    expect(Object.keys(READ_PARAMS).sort()).toEqual(reads);
  });

  describe.each(MODES)("over %s", (mode) => {
    const env = useDaemon(mode, { init: true });

    // scrub.* may only touch files under the home dir: give them a sandbox one.
    let home: string;
    let savedHome: { HOME?: string | undefined; USERPROFILE?: string | undefined };
    beforeEach(() => {
      savedHome = { HOME: process.env.HOME, USERPROFILE: process.env.USERPROFILE };
      home = fs.mkdtempSync(path.join(os.tmpdir(), "avr-"));
      process.env.HOME = home;
      process.env.USERPROFILE = home;
    });
    afterEach(() => {
      for (const [key, value] of Object.entries(savedHome)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      fs.rmSync(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    });

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

      // The browser path: the value goes in over HTTP and must not come back out anywhere.
      const begun = await env.client.call<{ url: string; elicitationId: string }>("capture.begin", {
        name: "leak/browser",
      });
      const page = await submit(begun.url, SECRET);
      const waited = await env.client.call("capture.wait", { elicitationId: begun.elicitationId });

      // helper.get must refuse a secret that is not tagged, with no value in the refusal.
      const refused = await env.client.call("helper.get", { secret: "leak/check" }).then(
        (value) => ({ value }),
        (err: unknown) => ({ message: (err as Error).message, data: (err as RpcError).data }),
      );
      expect(refused).not.toHaveProperty("value");

      // The scrubber reads the value to find it in a transcript; nothing it answers may carry it.
      const transcript = path.join(home, "transcript.jsonl");
      fs.writeFileSync(transcript, `${JSON.stringify({ text: SECRET })}\n`);
      const queued = await env.client.call("scrub.queue", {
        harness: "claude-code",
        files: [transcript],
        secretNames: ["leak/check"],
      });
      const scrubbed = await env.client.call("scrub.run", { harness: "claude-code" });
      expect(scrubbed).toMatchObject({ filesChanged: 1, replacements: 1 });
      expect(fs.readFileSync(transcript, "utf8")).not.toContain(SECRET);

      const responses: unknown[] = [put, begun, waited, page, refused, queued, scrubbed];
      for (const [method, def] of Object.entries(registry)) {
        if (def.mutates || SELF_AUDITED.has(method)) continue;
        responses.push(await env.client.call(method, READ_PARAMS[method]));
      }
      responses.push(await env.client.call("audit.query", { limit: 100 }));
      const wire = JSON.stringify(responses);
      for (const form of forms(SECRET)) expect(wire).not.toContain(form);
      expect(wire).toContain("leak/check");
      expect(wire).toContain("Stored as leak/browser");
    });
  });
});
