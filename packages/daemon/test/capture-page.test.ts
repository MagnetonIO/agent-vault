import http from "node:http";
import type { AuditEvent, SecretMeta } from "@agent-vault/core";
import { describe, expect, test } from "vitest";
import { escapeHtml, openCommand, openUrl } from "../src/capture-page.js";
import { b64, MODES, useDaemon } from "./helpers.js";

const SECRET = "ghp_aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bD1fH3jK5";
const TTL = 10 * 60_000;
const SELF_CSP = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'";

type Begun = { url: string; elicitationId: string; expiresAt: string };
type Waited =
  | { status: "stored"; name: string; type: string; length: number }
  | { status: "expired" };
type Res = { status: number; headers: http.IncomingHttpHeaders; body: string };

/** A raw HTTP request, so Host, Origin and the method can be set freely. */
function send(
  url: string,
  o: {
    method?: string;
    path?: string;
    headers?: Record<string, string>;
    body?: string | Buffer;
  } = {},
): Promise<Res> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const body = o.body === undefined ? undefined : Buffer.from(o.body);
    const req = http.request(
      {
        host: "127.0.0.1",
        port: u.port,
        method: o.method ?? "GET",
        path: o.path ?? u.pathname,
        agent: false,
        headers: {
          ...(body && { "content-length": String(body.length) }),
          ...o.headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

const form = (fields: Record<string, string>): string => new URLSearchParams(fields).toString();
const origin = (url: string): string => new URL(url).origin;

/** A same-origin form POST, as the browser would send it. */
function post(url: string, fields: Record<string, string>, extra: Record<string, string> = {}) {
  return send(url, {
    method: "POST",
    body: form(fields),
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      origin: origin(url),
      "sec-fetch-site": "same-origin",
      ...extra,
    },
  });
}

describe.each(MODES)("capture page over %s", (mode) => {
  let t = 1_000_000;
  const env = useDaemon(mode, { init: true, capture: { now: () => t } });
  const begin = (params?: object) => env.client.call<Begun>("capture.begin", params);

  test("capture.begin returns a loopback url with a 32-byte base64url nonce", async () => {
    const b = await begin();
    const u = new URL(b.url);
    expect(u.protocol).toBe("http:");
    expect(u.hostname).toBe("127.0.0.1");
    expect(u.port).not.toBe("");
    const m = /^\/capture\/([A-Za-z0-9_-]+)$/.exec(u.pathname);
    expect(m).not.toBeNull();
    expect(Buffer.from(m?.[1] ?? "", "base64url")).toHaveLength(32);
    expect(m?.[1]).toHaveLength(43);
    expect(b.elicitationId).toMatch(/^[0-9a-f-]{36}$/);
    expect(Date.parse(b.expiresAt) - t).toBe(TTL);
  });

  test("every capture.begin gets its own nonce, all on one server", async () => {
    const a = await begin();
    const b = await begin();
    expect(a.url).not.toBe(b.url);
    expect(new URL(a.url).port).toBe(new URL(b.url).port);
  });

  test("capture.begin rejects an invalid name and an unknown param", async () => {
    await expect(begin({ name: "Bad Name" })).rejects.toMatchObject({ code: -32602 });
    await expect(begin({ value: "x" })).rejects.toMatchObject({ code: -32602 });
  });

  test("GET returns the form with the brief's headers", async () => {
    const { url } = await begin();
    const res = await send(url);
    expect(res.status).toBe(200);
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers["content-security-policy"]).toMatch(
      new RegExp(`^${SELF_CSP.replace(/[()']/g, "\\$&")}`),
    );
    expect(res.headers["content-security-policy"]).toBe(
      `${SELF_CSP}; frame-ancestors 'none'; base-uri 'none'`,
    );
    expect(res.headers["x-frame-options"]).toBe("DENY");
    expect(res.headers["referrer-policy"]).toBe("no-referrer");
    expect(res.headers["x-content-type-options"]).toBe("nosniff");
    expect(res.headers["content-type"]).toMatch(/^text\/html/);
    expect(res.body).toContain('<input type="password" name="value" autocomplete="off" required>');
    expect(res.body).toContain('name="name"');
    expect(res.body).toContain("The agent only ever sees the name.");
    expect(res.body).not.toMatch(/<script|https?:\/\/(?!127\.0\.0\.1)/i);
  });

  test("the name given to capture.begin is prefilled and escaped", async () => {
    const { url } = await begin({ name: "gh/token" });
    expect((await send(url)).body).toContain('value="gh/token"');
  });

  test("the security headers are on every response", async () => {
    const { url } = await begin();
    const responses = [
      await send(url),
      await send(url, { path: "/" }),
      await send(url, { method: "PUT" }),
      await send(url, { headers: { host: "evil.com" } }),
      await send(url, { path: "/capture/unknownnonce" }),
      await post(url, { value: "" }),
    ];
    for (const res of responses) {
      expect(res.headers["cache-control"]).toBe("no-store");
      expect(res.headers["content-security-policy"]).toContain(SELF_CSP);
      expect(res.headers["x-frame-options"]).toBe("DENY");
      expect(res.headers["referrer-policy"]).toBe("no-referrer");
      expect(res.headers["x-content-type-options"]).toBe("nosniff");
    }
  });

  test("POST stores the secret and shows name · type · length only", async () => {
    const { url } = await begin({ name: "gh/token" });
    const res = await post(url, { name: "gh/token", value: SECRET });
    expect(res.status).toBe(200);
    expect(res.body).toContain("Stored as gh/token · generic · 40 chars");
    expect(res.body).not.toContain(SECRET);
    expect(res.body).not.toContain(Buffer.from(SECRET).toString("base64"));

    const list = await env.client.call<SecretMeta[]>("secret.list");
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ name: "gh/token", length: 40 });
  });

  test("a blank name goes through detection, like secret.put", async () => {
    const { url } = await begin();
    const res = await post(url, { name: "", value: SECRET });
    expect(res.status).toBe(200);
    const [meta] = await env.client.call<SecretMeta[]>("secret.list");
    expect(meta?.name).not.toMatch(/^secret\/unnamed-/);
    expect(meta?.type).not.toBe("generic");
    expect(res.body).toContain(`Stored as ${meta?.name} · ${meta?.type} · 40 chars`);

    const plain = await post((await begin()).url, { name: "", value: "just a password" });
    expect(plain.body).toMatch(/Stored as secret\/unnamed-\d{8} · generic · 15 chars/);
  });

  test("a second POST with the same nonce is 410, and GET too", async () => {
    const { url } = await begin();
    expect((await post(url, { value: SECRET })).status).toBe(200);
    expect((await post(url, { value: "another" })).status).toBe(410);
    expect((await send(url)).status).toBe(410);
    expect(await env.client.call<SecretMeta[]>("secret.list")).toHaveLength(1);
  });

  test("a POST after 10 minutes is 410 and stores nothing", async () => {
    const { url } = await begin();
    t += TTL - 1;
    expect((await send(url)).status).toBe(200);
    t += 1;
    expect((await post(url, { value: SECRET })).status).toBe(410);
    expect((await send(url)).status).toBe(410);
    expect(await env.client.call<SecretMeta[]>("secret.list")).toEqual([]);
  });

  test("an unknown nonce is 410", async () => {
    const { url } = await begin();
    expect((await send(url, { path: "/capture/AAAA" })).status).toBe(410);
  });

  test("Host: evil.com is 421, including for DNS rebinding hosts", async () => {
    const { url } = await begin();
    const port = new URL(url).port;
    for (const host of ["evil.com", `attacker.example:${port}`, "127.0.0.1", `localhost:${port}`]) {
      expect((await send(url, { headers: { host } })).status).toBe(421);
      expect((await post(url, { value: SECRET }, { host })).status).toBe(421);
    }
    expect(await env.client.call<SecretMeta[]>("secret.list")).toEqual([]);
    // The nonce survived all of that.
    expect((await post(url, { value: SECRET })).status).toBe(200);
  });

  test("Host is checked before the route: a bad Host on / is 421, not 404", async () => {
    const { url } = await begin();
    expect((await send(url, { path: "/", headers: { host: "evil.com" } })).status).toBe(421);
  });

  test("an Origin that is not this page is 403; no Origin is 403", async () => {
    const { url } = await begin();
    for (const o of ["http://evil.com", "http://localhost:1", "null", `${origin(url)}.evil.com`]) {
      expect((await post(url, { value: SECRET }, { origin: o })).status).toBe(403);
    }
    const noOrigin = await send(url, {
      method: "POST",
      body: form({ value: SECRET }),
      headers: { "content-type": "application/x-www-form-urlencoded" },
    });
    expect(noOrigin.status).toBe(403);
    expect(await env.client.call<SecretMeta[]>("secret.list")).toEqual([]);
    expect((await post(url, { value: SECRET })).status).toBe(200);
  });

  test("Sec-Fetch-Site other than same-origin is 403; absent is allowed", async () => {
    const { url } = await begin();
    for (const site of ["cross-site", "same-site", "none"]) {
      expect((await post(url, { value: SECRET }, { "sec-fetch-site": site })).status).toBe(403);
    }
    const res = await send(url, {
      method: "POST",
      body: form({ value: SECRET }),
      headers: { "content-type": "application/x-www-form-urlencoded", origin: origin(url) },
    });
    expect(res.status).toBe(200);
  });

  test("an empty value is 400 and keeps the nonce", async () => {
    const { url } = await begin();
    const res = await post(url, { name: "gh/token", value: "" });
    expect(res.status).toBe(400);
    expect(res.body).toContain('<input type="password" name="value"');
    expect(await env.client.call<SecretMeta[]>("secret.list")).toEqual([]);
    expect((await post(url, { name: "gh/token", value: SECRET })).status).toBe(200);
  });

  test("a missing value field is 400 and keeps the nonce", async () => {
    const { url } = await begin();
    expect((await post(url, { name: "gh/token" })).status).toBe(400);
    expect((await post(url, { value: SECRET })).status).toBe(200);
  });

  test("an invalid name is 400, escaped in the page, and keeps the nonce", async () => {
    const { url } = await begin();
    const res = await post(url, { name: '"><script>alert(1)</script>', value: SECRET });
    expect(res.status).toBe(400);
    expect(res.body).not.toContain("<script>alert");
    expect(res.body).toContain("&lt;script&gt;");
    expect(res.body).not.toContain(SECRET);
    expect((await post(url, { value: SECRET })).status).toBe(200);
  });

  test("escapeHtml escapes the five HTML metacharacters", () => {
    expect(escapeHtml(`<a href="x" onclick='y'>&</a>`)).toBe(
      "&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;",
    );
  });

  test("a value with form-encoding characters is stored exactly", async () => {
    const value = "p&ss=w+rd %41 é✓ /?#";
    const { url } = await begin();
    expect((await post(url, { name: "odd/value", value })).status).toBe(200);
    const [meta] = await env.client.call<SecretMeta[]>("secret.list");
    expect(meta).toMatchObject({ name: "odd/value", length: Buffer.byteLength(value) });
  });

  test("the audit log gets a captured event, without the value", async () => {
    const { url } = await begin({ harness: "codex" });
    await post(url, { name: "gh/token", value: SECRET });
    const events = await env.client.call<AuditEvent[]>("audit.query");
    const e = events.find((x) => x.operation === "capture");
    expect(e).toMatchObject({
      outcome: "captured",
      secretName: "gh/token",
      harness: "codex",
      actor: "capture",
    });
    expect(e?.deviceId).toMatch(/^dev-[0-9a-f]{12}$/);
    expect(JSON.stringify(events)).not.toContain(SECRET);
    expect(await env.client.call("audit.verify")).toEqual({ ok: true });
  });

  test("other routes are 404, other methods are 405 with Allow", async () => {
    const { url } = await begin();
    for (const path of ["/", "/capture", "/capture/", "/favicon.ico", "/capture/a/b", "/x"]) {
      expect((await send(url, { path })).status).toBe(404);
    }
    for (const method of ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]) {
      const res = await send(url, { method });
      expect(res.status).toBe(405);
      expect(res.headers.allow).toBe("GET, POST");
    }
    expect((await send(url)).status).toBe(200);
  });

  test("a body over 64 KiB is 413 and keeps the nonce", async () => {
    const { url } = await begin();
    const big = form({ value: "x".repeat(64 * 1024 + 1) });
    const res = await send(url, {
      method: "POST",
      body: big,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        origin: origin(url),
        "sec-fetch-site": "same-origin",
      },
    });
    expect(res.status).toBe(413);
    expect(await env.client.call<SecretMeta[]>("secret.list")).toEqual([]);
    expect((await post(url, { value: SECRET })).status).toBe(200);
  });

  test("a body of exactly 64 KiB is accepted", async () => {
    const { url } = await begin();
    const prefix = "value=";
    const res = await send(url, {
      method: "POST",
      body: prefix + "x".repeat(64 * 1024 - prefix.length),
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        origin: origin(url),
      },
    });
    expect(res.status).toBe(200);
  });

  test("a POST that is not form-urlencoded is 415 and keeps the nonce", async () => {
    const { url } = await begin();
    for (const type of ["application/json", "text/plain", "multipart/form-data; boundary=x"]) {
      const res = await post(url, { value: SECRET }, { "content-type": type });
      expect(res.status).toBe(415);
    }
    expect((await post(url, { value: SECRET })).status).toBe(200);
  });

  test("the form-urlencoded content type may carry a charset", async () => {
    const { url } = await begin();
    const res = await post(
      url,
      { value: SECRET },
      { "content-type": "application/x-www-form-urlencoded; charset=UTF-8" },
    );
    expect(res.status).toBe(200);
  });

  test("capture.wait resolves after the POST with name, type and length", async () => {
    const { url, elicitationId } = await begin();
    const waiting = env.client.call<Waited>("capture.wait", { elicitationId });
    await post(url, { name: "gh/token", value: SECRET });
    expect(await waiting).toEqual({
      status: "stored",
      name: "gh/token",
      type: "generic",
      length: 40,
    });
    // Asking again after the fact gives the same answer.
    expect(await env.client.call("capture.wait", { elicitationId })).toEqual({
      status: "stored",
      name: "gh/token",
      type: "generic",
      length: 40,
    });
  });

  test("capture.wait does not resolve while the page is still open", async () => {
    const { elicitationId } = await begin();
    const result = await env.client.call<Waited>("capture.wait", { elicitationId, timeoutMs: 100 });
    expect(result).toEqual({ status: "expired" });
  });

  test("capture.wait after the TTL, and for an unknown id, is expired", async () => {
    const { elicitationId } = await begin();
    t += TTL;
    expect(await env.client.call("capture.wait", { elicitationId })).toEqual({ status: "expired" });
    expect(
      await env.client.call("capture.wait", {
        elicitationId: "00000000-0000-4000-8000-000000000000",
      }),
    ).toEqual({ status: "expired" });
  });

  test("capture.wait validates its params", async () => {
    const bad = [
      {},
      { elicitationId: 1 },
      { elicitationId: "x", timeoutMs: -1 },
      { elicitationId: "x", timeoutMs: 600_001 },
      { elicitationId: "x", timeoutMs: 1.5 },
    ];
    for (const p of bad)
      await expect(env.client.call("capture.wait", p)).rejects.toMatchObject({ code: -32602 });
  });

  test("capture.begin and capture.wait are never secret-returning and write no audit event", async () => {
    const { url, elicitationId } = await begin();
    await env.client.call("capture.wait", { elicitationId, timeoutMs: 1 });
    const events = await env.client.call<AuditEvent[]>("audit.query");
    expect(events.map((e) => e.operation)).toEqual(["vault.init"]);
    await post(url, { value: SECRET });
  });
});

describe.each(MODES)("capture page expiry on the real clock over %s", (mode) => {
  const env = useDaemon(mode, { init: true, capture: { ttlMs: 150 } });

  test("capture.wait returns expired when the TTL passes with no POST", async () => {
    const { elicitationId } = await env.client.call<Begun>("capture.begin");
    const start = Date.now();
    expect(await env.client.call("capture.wait", { elicitationId })).toEqual({ status: "expired" });
    expect(Date.now() - start).toBeLessThan(5000);
  });
});

describe("capture before the vault exists", () => {
  const env = useDaemon(MODES[0] ?? "tcp", {});
  test("capture.begin needs an initialized vault", async () => {
    await expect(env.client.call("capture.begin")).rejects.toMatchObject({
      data: { name: "VaultNotInitializedError" },
    });
  });
});

describe.each(MODES)("a failed store over %s", (mode) => {
  const env = useDaemon(mode, {
    init: true,
    capture: {
      store: () => {
        throw new Error(`disk on fire ${SECRET}`);
      },
    },
  });

  test("consumes the nonce, says to start again and leaks nothing", async () => {
    const { url, elicitationId } = await env.client.call<Begun>("capture.begin", {
      name: "gh/token",
    });
    const res = await post(url, { name: "gh/token", value: SECRET });
    expect(res.status).toBe(500);
    expect(res.body).toContain("Start again");
    expect(res.body).not.toContain(SECRET);
    expect(res.body).not.toContain("disk on fire");

    expect((await post(url, { name: "gh/token", value: SECRET })).status).toBe(410);
    expect(await env.client.call("capture.wait", { elicitationId })).toEqual({ status: "expired" });

    const events = await env.client.call<AuditEvent[]>("audit.query");
    const e = events.find((x) => x.operation === "capture");
    expect(e).toMatchObject({ outcome: "error", secretName: "gh/token" });
    expect(JSON.stringify(events)).not.toContain(SECRET);
  });
});

describe("daemon close", () => {
  const env = useDaemon(MODES[0] ?? "tcp", { init: true });

  test("close stops the capture server", async () => {
    const { url } = await env.client.call<Begun>("capture.begin");
    expect((await send(url)).status).toBe(200);
    await env.daemon.close();
    await expect(send(url)).rejects.toThrow();
  });

  test("the value is not logged: a stored value never reaches the wire of other RPCs", async () => {
    const { url } = await env.client.call<Begun>("capture.begin");
    await post(url, { name: "x/y", value: SECRET });
    const wire = JSON.stringify([
      await env.client.call("secret.list"),
      await env.client.call("audit.query"),
    ]);
    expect(wire).not.toContain(SECRET);
    expect(wire).not.toContain(b64(SECRET));
  });
});

describe("openCommand", () => {
  const url = "http://127.0.0.1:4242/capture/abc";
  test("uses the platform opener without a shell", () => {
    expect(openCommand(url, "darwin")).toEqual({ file: "/usr/bin/open", args: [url] });
    expect(openCommand(url, "linux")).toEqual({ file: "xdg-open", args: [url] });
    expect(openCommand(url, "win32")).toEqual({
      file: "rundll32.exe",
      args: ["url.dll,FileProtocolHandler", url],
    });
  });

  test("refuses anything but an http(s) url, so it cannot become an option or a file", async () => {
    for (const bad of ["-h", "file:///etc/passwd", "javascript:alert(1)", "calc.exe", ""]) {
      expect(() => openCommand(bad, "linux")).toThrow(/http/);
      await expect(openUrl(bad)).rejects.toThrow(/http/);
    }
  });
});
