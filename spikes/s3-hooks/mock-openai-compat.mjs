#!/usr/bin/env node
import { appendFileSync } from "node:fs";
// Spike S3: local OpenAI-compatible /chat/completions stand-in for OpenCode. Logs canary/redaction flags, replies "ok".
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
      const chunk = (delta, finish) =>
        `data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", created: 1, model: "m", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write(chunk({ role: "assistant", content: "ok" }, null));
      res.write(chunk({}, "stop"));
      res.write(
        `data: ${JSON.stringify({ id: "c1", object: "chat.completion.chunk", created: 1, model: "m", choices: [], usage: { prompt_tokens: 1, completion_tokens: 1, total_tokens: 2 } })}\n\n`,
      );
      res.end("data: [DONE]\n\n");
    });
  })
  .listen(Number(process.env.MOCK_PORT), "127.0.0.1");
