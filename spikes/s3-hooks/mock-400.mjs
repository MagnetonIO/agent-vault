#!/usr/bin/env node
import { appendFileSync } from "node:fs";
// Spike S3: local stand-in model endpoint. Logs whether the request body carries the canary / redaction marker, then fails fast with 400.
import http from "node:http";

http
  .createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      appendFileSync(
        process.env.MOCK_LOG,
        `${JSON.stringify({
          url: req.url,
          bytes: body.length,
          bodyHasCanary: body.includes(process.env.AVCANARY_VALUE),
          bodyHasRedacted: body.includes("[REDACTED:vault]"),
        })}\n`,
      );
      res.writeHead(400, { "content-type": "application/json" });
      res.end('{"error":{"message":"mock: no model","type":"invalid_request_error"}}');
    });
  })
  .listen(Number(process.env.MOCK_PORT), "127.0.0.1");
