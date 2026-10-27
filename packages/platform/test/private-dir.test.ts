import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { ensurePrivateDir, icaclsCommands, icaclsExe } from "../src/index.js";

const posix = process.platform !== "win32";
let tmp: string;

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), "av-private-dir-"));
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tmp, { recursive: true, force: true });
});

describe.skipIf(!posix)("ensurePrivateDir (POSIX)", () => {
  const mode = (p: string) => fs.statSync(p).mode & 0o777;

  test("creates the dir, including parents, as 0700", () => {
    const dir = path.join(tmp, "a", "b", "run");
    ensurePrivateDir(dir);
    expect(mode(dir)).toBe(0o700);
  });

  test("creates 0700 even under a permissive umask", () => {
    const old = process.umask(0o000);
    try {
      const dir = path.join(tmp, "open-umask");
      ensurePrivateDir(dir);
      expect(mode(dir)).toBe(0o700);
    } finally {
      process.umask(old);
    }
  });

  test("tightens a loose existing dir to 0700", () => {
    const dir = path.join(tmp, "loose");
    fs.mkdirSync(dir, { mode: 0o755 });
    fs.chmodSync(dir, 0o777);
    ensurePrivateDir(dir);
    expect(mode(dir)).toBe(0o700);
  });

  test("leaves a stricter dir alone", () => {
    const dir = path.join(tmp, "strict");
    fs.mkdirSync(dir);
    fs.chmodSync(dir, 0o500);
    ensurePrivateDir(dir);
    expect(mode(dir)).toBe(0o500);
    fs.chmodSync(dir, 0o700);
  });

  test("is idempotent and returns void", () => {
    const dir = path.join(tmp, "twice");
    expect(ensurePrivateDir(dir)).toBeUndefined();
    expect(ensurePrivateDir(dir)).toBeUndefined();
    expect(mode(dir)).toBe(0o700);
  });

  test("throws when the dir is owned by another uid, and does not chmod it", () => {
    const dir = path.join(tmp, "foreign");
    fs.mkdirSync(dir);
    fs.chmodSync(dir, 0o777);
    const uid = process.getuid?.() ?? 0;
    vi.spyOn(process, "getuid").mockReturnValue(uid + 1);
    expect(() => ensurePrivateDir(dir)).toThrow(/owned by uid/);
    expect(mode(dir)).toBe(0o777);
  });

  test("refuses a symlink, even one that points at a dir we own", () => {
    const real = path.join(tmp, "real");
    fs.mkdirSync(real);
    const link = path.join(tmp, "link");
    fs.symlinkSync(real, link);
    expect(() => ensurePrivateDir(link)).toThrow(/symlink or junction/);
  });

  test("refuses a regular file", () => {
    const file = path.join(tmp, "file");
    fs.writeFileSync(file, "x");
    expect(() => ensurePrivateDir(file)).toThrow();
  });
});

// The lstat checks run before icacls, so these work on any OS with platform = "win32".
describe("ensurePrivateDir refuses links and files before touching ACLs (win32 path)", () => {
  test("symlink to a dir", () => {
    if (!posix) return; // Windows symlinks need privileges; the junction test below covers it
    const real = path.join(tmp, "real");
    fs.mkdirSync(real);
    const link = path.join(tmp, "link");
    fs.symlinkSync(real, link);
    expect(() => ensurePrivateDir(link, "win32")).toThrow(/symlink or junction/);
  });

  test("regular file", () => {
    const file = path.join(tmp, "file");
    fs.writeFileSync(file, "x");
    expect(() => ensurePrivateDir(file, "win32")).toThrow();
  });

  test.skipIf(posix)("junction (real Windows)", () => {
    const real = path.join(tmp, "real");
    fs.mkdirSync(real);
    const link = path.join(tmp, "junction");
    fs.symlinkSync(real, link, "junction");
    expect(() => ensurePrivateDir(link)).toThrow(/symlink or junction/);
  });
});

describe("icaclsExe", () => {
  test("is System32\\icacls.exe under SystemRoot, with a default", () => {
    expect(icaclsExe({ SystemRoot: "D:\\WIN" })).toBe("D:\\WIN\\System32\\icacls.exe");
    expect(icaclsExe({})).toBe("C:\\Windows\\System32\\icacls.exe");
  });
});

describe("icaclsCommands", () => {
  test("grants the user, drops inheritance, then removes SYSTEM and Administrators by SID", () => {
    expect(icaclsCommands("C:\\d", "carol")).toEqual([
      ["C:\\d", "/inheritance:r", "/grant:r", "carol:(OI)(CI)F"],
      ["C:\\d", "/remove", "*S-1-5-18", "/remove", "*S-1-5-32-544"],
    ]);
  });
});

describe.skipIf(posix)("ensurePrivateDir (Windows, real icacls)", () => {
  test("leaves only the current user on the dir ACL", () => {
    const dir = path.join(tmp, "locked");
    ensurePrivateDir(dir);
    const acl = execFileSync(icaclsExe(), [dir], { encoding: "utf8" });
    expect(acl).toContain(os.userInfo().username);
    expect(acl).not.toContain("NT AUTHORITY\\SYSTEM");
    expect(acl).not.toContain("BUILTIN\\Administrators");
  });
});
