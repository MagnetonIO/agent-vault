import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { fakes } from "../../detect/test/fixtures/fake-keys.js";
import { historyFiles, scanHistory } from "../src/index.js";

let dir: string;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "avs-"));
});
afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
});

const put = (rel: string, data: string | Buffer): string => {
  const file = path.join(dir, rel);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, data);
  return file;
};

describe("historyFiles", () => {
  test("finds Claude, Codex and OpenCode text files and skips databases and binaries", () => {
    const want = [
      put("home/.claude/projects/p1/a.jsonl", "{}\n"),
      put("home/.claude/projects/p1/deep/b.jsonl", "{}\n"),
      put("home/.claude/history.jsonl", "{}\n"),
      put("codex/history.jsonl", "{}\n"),
      put("codex/sessions/2026/10/27/rollout.jsonl", "{}\n"),
      put("home/.local/share/opencode/log/x.log", "line\n"),
      put("xdg/opencode/storage/session.json", "{}\n"),
    ].sort();
    put("home/.claude/projects/p1/notes.txt", "not a transcript\n");
    put("home/.local/share/opencode/opencode.db", "text but a database\n");
    put("home/.local/share/opencode/opencode.db-wal", "x");
    put("home/.local/share/opencode/blob", Buffer.from([1, 2, 0, 3]));
    const found = historyFiles({
      home: path.join(dir, "home"),
      codexHome: path.join(dir, "codex"),
      xdgDataHome: path.join(dir, "xdg"),
    });
    expect(found).toEqual(want);
  });

  test("a machine with none of them gives an empty list", () => {
    expect(historyFiles({ home: path.join(dir, "nothing") })).toEqual([]);
  });
});

describe("scanHistory", () => {
  test("returns one fingerprint per distinct secret per file, never a value", async () => {
    const PAT = fakes.githubPat();
    const OPENAI = fakes.openai();
    const dirty = put(
      "dirty.jsonl",
      [
        JSON.stringify({ text: `export GITHUB_TOKEN=${PAT}` }),
        JSON.stringify({ text: `again ${PAT} and ${OPENAI}` }),
        "plain line",
      ].join("\n"),
    );
    const clean = put("clean.jsonl", `${JSON.stringify({ text: "nothing here" })}\n`);
    const hits = await scanHistory([dirty, clean, path.join(dir, "missing.jsonl")]);
    expect(hits).toHaveLength(1);
    expect(hits[0]?.file).toBe(dirty);
    expect(hits[0]?.fingerprints).toHaveLength(2);
    for (const fp of hits[0]?.fingerprints ?? []) {
      expect(fp).toMatch(/^[a-z0-9-]+ len=\d+ sha256:[0-9a-f]{8}$/);
    }
    const out = JSON.stringify(hits);
    expect(out).not.toContain(PAT);
    expect(out).not.toContain(OPENAI);
  });

  test("a line with a 9 MiB base64 run is scanned, not skipped, and the key beside it is found", async () => {
    const KEY = fakes.anthropic();
    const blob = randomBytes(7 * 1024 * 1024).toString("base64"); // one run of about 9.3 MiB
    const file = put("big.jsonl", `${JSON.stringify({ text: `${KEY} ${blob}` })}\n`);
    const warnings: string[] = [];
    const hits = await scanHistory([file], { warn: (m) => warnings.push(m) });
    expect(warnings).toEqual([]);
    expect(hits[0]?.fingerprints.some((fp) => fp.startsWith("anthropic "))).toBe(true);
  });

  test("a secret inside a JSON-escaped multi-line string is found", async () => {
    const file = put(
      "e.jsonl",
      `${JSON.stringify({ text: `A=1\nTOKEN=${fakes.slack()}\nB=2` })}\n`,
    );
    expect((await scanHistory([file]))[0]?.fingerprints).toHaveLength(1);
  });
});
