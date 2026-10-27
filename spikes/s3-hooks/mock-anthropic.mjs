#!/usr/bin/env node
import { appendFileSync } from "node:fs";
// Spike S3 step 4: local fake Anthropic API. Answers the first agent turn with a Bash tool_use
// (`env | grep -c AVCANARY_`) and the follow-up with text. Logs request headers (key redacted) and tool_result.
import http from "node:http";

const log = (o) => appendFileSync(process.env.MOCK_LOG, `${JSON.stringify(o)}\n`);
const canary = process.env.AVCANARY_VALUE ?? "";
const sse = (res, events) => {
  res.writeHead(200, { "content-type": "text/event-stream" });
  for (const [e, d] of events) res.write(`event: ${e}\ndata: ${JSON.stringify(d)}\n\n`);
  res.end();
};
const msg = (content, stop) => ({
  id: "msg_mock",
  type: "message",
  role: "assistant",
  model: "mock",
  content,
  stop_reason: stop,
  stop_sequence: null,
  usage: { input_tokens: 1, output_tokens: 1 },
});
http
  .createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const redact = (v) => (v ? String(v).replaceAll(canary, "<CANARY>") : v);
      let j = {};
      try {
        j = JSON.parse(body);
      } catch {}
      const hasBash = (j.tools ?? []).some((t) => t.name === "Bash");
      const trIdx = body.indexOf('"tool_result"');
      log({
        url: req.url,
        "x-api-key": redact(req.headers["x-api-key"]),
        authorization: redact(req.headers.authorization),
        stream: j.stream,
        hasBash,
        hasToolResult: trIdx >= 0,
        bodyHasCanary: canary !== "" && body.includes(canary),
        bodyHasRedacted: body.includes("[REDACTED:vault]"),
      });
      if (trIdx >= 0) {
        const toolResults = (j.messages ?? [])
          .flatMap((m) => (Array.isArray(m.content) ? m.content : []))
          .filter((b) => b.type === "tool_result");
        log({ tool_result: toolResults.map((b) => redact(JSON.stringify(b.content))) });
      }
      const wantsTool = hasBash && trIdx < 0 && body.includes("RUNENVPROBE");
      const content = wantsTool
        ? [
            {
              type: "tool_use",
              id: "toolu_mock1",
              name: "Bash",
              input: { command: "env | grep -c AVCANARY_" },
            },
          ]
        : [{ type: "text", text: "ok" }];
      const stop = wantsTool ? "tool_use" : "end_turn";
      if (!j.stream) {
        res.writeHead(200, { "content-type": "application/json" });
        return res.end(JSON.stringify(msg(content, stop)));
      }
      const ev = [["message_start", { type: "message_start", message: msg([], null) }]];
      content.forEach((b, i) => {
        if (b.type === "tool_use") {
          ev.push([
            "content_block_start",
            { type: "content_block_start", index: i, content_block: { ...b, input: {} } },
          ]);
          ev.push([
            "content_block_delta",
            {
              type: "content_block_delta",
              index: i,
              delta: { type: "input_json_delta", partial_json: JSON.stringify(b.input) },
            },
          ]);
        } else {
          ev.push([
            "content_block_start",
            { type: "content_block_start", index: i, content_block: { type: "text", text: "" } },
          ]);
          ev.push([
            "content_block_delta",
            { type: "content_block_delta", index: i, delta: { type: "text_delta", text: b.text } },
          ]);
        }
        ev.push(["content_block_stop", { type: "content_block_stop", index: i }]);
      });
      ev.push(
        [
          "message_delta",
          {
            type: "message_delta",
            delta: { stop_reason: stop, stop_sequence: null },
            usage: { output_tokens: 2 },
          },
        ],
        ["message_stop", { type: "message_stop" }],
      );
      sse(res, ev);
    });
  })
  .listen(Number(process.env.MOCK_PORT ?? 0), "127.0.0.1", function () {
    console.log(this.address().port);
  });
