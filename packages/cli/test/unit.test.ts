import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { getPaths } from "@agent-vault/platform";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { formatWords } from "../src/commands/init.js";
import { parseWords } from "../src/commands/recover.js";
import { parseEnvRefs } from "../src/commands/run.js";
import { readConfig, restoreConfig, snapshotConfig, writeConfig } from "../src/config.js";
import { CliError } from "../src/errors.js";
import { table } from "../src/output.js";

describe("formatWords", () => {
  test("numbers the words and puts four on a line", () => {
    const words = Array.from({ length: 24 }, (_, i) => `w${i + 1}`);
    const lines = formatWords(words);
    expect(lines).toHaveLength(6);
    expect(lines[0]).toMatch(/^ 1\. w1\s+ 2\. w2\s+ 3\. w3\s+ 4\. w4$/);
    expect(lines[5]).toMatch(/^21\. w21\s+22\. w22\s+23\. w23\s+24\. w24$/);
  });
});

describe("parseWords", () => {
  test("accepts any spacing, commas, case and numbering", () => {
    expect(parseWords(" 1. Alpha, beta\tGAMMA  2) delta 3 epsilon ")).toEqual([
      "alpha",
      "beta",
      "gamma",
      "delta",
      "epsilon",
    ]);
  });
});

describe("parseEnvRefs", () => {
  test("splits at the first =", () => {
    expect(parseEnvRefs(["A=vault://x", "B=vault://y/z"])).toEqual({
      A: "vault://x",
      B: "vault://y/z",
    });
  });

  test("rejects a pair with no name or no =, without echoing the value", () => {
    for (const bad of ["nonsense", "=vault://x"]) {
      expect(() => parseEnvRefs([bad])).toThrow(CliError);
    }
    try {
      parseEnvRefs(["TOKEN-ish"]);
    } catch (err) {
      expect((err as CliError).exitCode).toBe(2);
    }
  });

  test("a name like __proto__ is an ordinary key", () => {
    const env = parseEnvRefs(["__proto__=vault://x"]);
    expect(Object.keys(env)).toEqual(["__proto__"]);
    expect(Object.getPrototypeOf(env)).toBe(Object.prototype);
  });
});

describe("table", () => {
  test("pads every column but the last", () => {
    expect(
      table([
        ["a", "bb", "c"],
        ["dddd", "e", ""],
      ]),
    ).toEqual(["a     bb  c", "dddd  e"]);
  });
});

describe("config.json", () => {
  let dir: string;
  let paths: ReturnType<typeof getPaths>;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "avcfg-"));
    paths = getPaths({ AGENT_VAULT_HOME: dir }, process.platform);
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  test("defaults to the OS keyring when absent", () => {
    expect(readConfig(paths)).toBe("os");
  });

  test("round-trips, owner-only on POSIX, with no temp file left", () => {
    writeConfig(paths, "keyfile");
    expect(readConfig(paths)).toBe("keyfile");
    if (process.platform !== "win32") {
      expect(fs.statSync(path.join(dir, "config.json")).mode & 0o777).toBe(0o600);
    }
    expect(fs.readdirSync(dir).filter((f) => f.endsWith(".tmp"))).toEqual([]);
  });

  test("restoreConfig puts back the old file, or removes the new one", () => {
    writeConfig(paths, "os");
    const before = snapshotConfig(paths);
    writeConfig(paths, "keyfile");
    restoreConfig(paths, before);
    expect(readConfig(paths)).toBe("os");
    fs.rmSync(path.join(dir, "config.json"));
    writeConfig(paths, "keyfile");
    restoreConfig(paths, null);
    expect(fs.existsSync(path.join(dir, "config.json"))).toBe(false);
  });

  test("an unknown or malformed config is an error, not a guess", () => {
    for (const text of ['{"keystore":"memory"}', "not json", "null"]) {
      fs.writeFileSync(path.join(dir, "config.json"), text);
      expect(() => readConfig(paths)).toThrow(CliError);
    }
  });
});
