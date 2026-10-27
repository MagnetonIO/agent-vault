import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";
import { getPaths, ipcEndpoint } from "../src/index.js";

const bytes = (s: string) => Buffer.byteLength(s);
const sha16 = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 16);

describe("ipcEndpoint", () => {
  test("darwin: unix socket in runtimeDir", () => {
    const paths = getPaths({ HOME: "/Users/alice" }, "darwin");
    expect(ipcEndpoint(paths, "darwin", {})).toEqual({
      kind: "unix",
      path: "/Users/alice/Library/Application Support/agent-vault/run/vaultd.sock",
    });
  });

  test("linux: unix socket under XDG_RUNTIME_DIR", () => {
    const paths = getPaths({ HOME: "/home/b", XDG_RUNTIME_DIR: "/run/user/1000" }, "linux");
    expect(ipcEndpoint(paths, "linux", {})).toEqual({
      kind: "unix",
      path: "/run/user/1000/agent-vault/vaultd.sock",
    });
  });

  test("win32: tcp with endpoint and token files, never a pipe", () => {
    const paths = getPaths({ LOCALAPPDATA: "C:\\Users\\C\\AppData\\Local" }, "win32");
    const ep = ipcEndpoint(paths, "win32", {});
    expect(ep).toEqual({
      kind: "tcp",
      endpointFile: "C:\\Users\\C\\AppData\\Local\\agent-vault\\run\\endpoint.json",
      tokenFile: "C:\\Users\\C\\AppData\\Local\\agent-vault\\run\\token",
    });
  });

  describe("length limit (UTF-8 bytes)", () => {
    const withRuntimeDir = (runtimeDir: string) => ({
      ...getPaths({ HOME: "/h" }, "linux"),
      runtimeDir,
    });
    // "/vaultd.sock" is 12 bytes
    const dirOfBytes = (n: number) => `/${"a".repeat(n - 1)}`;

    test("darwin: 103 bytes stays, 104 falls back", () => {
      const ok = ipcEndpoint(withRuntimeDir(dirOfBytes(103 - 12)), "darwin", { TMPDIR: "/t" });
      expect(ok.kind === "unix" && bytes(ok.path)).toBe(103);
      expect(ok.kind === "unix" && ok.path.startsWith("/a")).toBe(true);

      const long = withRuntimeDir(dirOfBytes(104 - 12));
      const fb = ipcEndpoint(long, "darwin", { TMPDIR: "/t" });
      expect(fb.kind).toBe("unix");
    });

    test("linux: 107 bytes stays, 108 falls back", () => {
      const ok = ipcEndpoint(withRuntimeDir(dirOfBytes(107 - 12)), "linux", { TMPDIR: "/t" });
      expect(ok.kind === "unix" && bytes(ok.path)).toBe(107);
      expect(ok.kind === "unix" && ok.path.startsWith("/a")).toBe(true);

      const fb = ipcEndpoint(withRuntimeDir(dirOfBytes(108 - 12)), "linux", { TMPDIR: "/t" });
      expect(fb.kind === "unix" && fb.path.startsWith("/a")).toBe(false);
    });

    test("fallback is <tmpdir>/av-<uid>/<sha256(full path)[0:16]>.sock", () => {
      const xdg = `/run/user/1000/${"x".repeat(120)}`;
      const paths = getPaths({ HOME: "/h", XDG_RUNTIME_DIR: xdg }, "linux");
      const full = `${paths.runtimeDir}/vaultd.sock`;
      const uid = process.getuid?.() ?? 0;
      expect(ipcEndpoint(paths, "linux", { TMPDIR: "/tmp" })).toEqual({
        kind: "unix",
        path: `/tmp/av-${uid}/${sha16(full)}.sock`,
      });
    });

    test("fallback is deterministic, so client and daemon agree", () => {
      const paths = getPaths({ HOME: "/h", XDG_RUNTIME_DIR: `/r/${"x".repeat(120)}` }, "linux");
      expect(ipcEndpoint(paths, "linux", { TMPDIR: "/tmp" })).toEqual(
        ipcEndpoint(paths, "linux", { TMPDIR: "/tmp" }),
      );
    });

    test("multibyte path under the limit in chars but over it in bytes falls back", () => {
      const xdg = `/r/${"é".repeat(50)}`; // 53 chars, 103 bytes
      const paths = getPaths({ HOME: "/h", XDG_RUNTIME_DIR: xdg }, "linux");
      const full = `${paths.runtimeDir}/vaultd.sock`;
      expect(full.length).toBeLessThanOrEqual(107);
      expect(bytes(full)).toBeGreaterThan(107);
      const ep = ipcEndpoint(paths, "linux", { TMPDIR: "/tmp" });
      expect(ep.kind === "unix" && ep.path).toBe(
        `/tmp/av-${process.getuid?.() ?? 0}/${sha16(full)}.sock`,
      );
    });

    test("multibyte path whose bytes fit stays put", () => {
      const xdg = `/r/${"é".repeat(30)}`;
      const paths = getPaths({ HOME: "/h", XDG_RUNTIME_DIR: xdg }, "linux");
      const ep = ipcEndpoint(paths, "linux", { TMPDIR: "/tmp" });
      expect(ep.kind === "unix" && ep.path).toBe(`${paths.runtimeDir}/vaultd.sock`);
    });

    test("throws when even the fallback is too long", () => {
      const paths = getPaths({ HOME: "/h", XDG_RUNTIME_DIR: `/r/${"x".repeat(120)}` }, "linux");
      expect(() => ipcEndpoint(paths, "linux", { TMPDIR: `/${"t".repeat(120)}` })).toThrow(
        /too long/,
      );
    });
  });
});
