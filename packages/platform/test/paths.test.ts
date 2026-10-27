import { describe, expect, test } from "vitest";
import { getPaths } from "../src/index.js";

describe("getPaths", () => {
  const cases: {
    name: string;
    platform: NodeJS.Platform;
    env: Record<string, string>;
    dataDir: string;
    runtimeDir: string;
    backupsDir: string;
    dbFile: string;
  }[] = [
    {
      name: "darwin",
      platform: "darwin",
      env: { HOME: "/Users/alice" },
      dataDir: "/Users/alice/Library/Application Support/agent-vault",
      runtimeDir: "/Users/alice/Library/Application Support/agent-vault/run",
      backupsDir: "/Users/alice/Library/Application Support/agent-vault/backups",
      dbFile: "/Users/alice/Library/Application Support/agent-vault/vault.db",
    },
    {
      name: "darwin ignores XDG vars",
      platform: "darwin",
      env: { HOME: "/Users/alice", XDG_DATA_HOME: "/x", XDG_RUNTIME_DIR: "/y" },
      dataDir: "/Users/alice/Library/Application Support/agent-vault",
      runtimeDir: "/Users/alice/Library/Application Support/agent-vault/run",
      backupsDir: "/Users/alice/Library/Application Support/agent-vault/backups",
      dbFile: "/Users/alice/Library/Application Support/agent-vault/vault.db",
    },
    {
      name: "linux with XDG_DATA_HOME and XDG_RUNTIME_DIR",
      platform: "linux",
      env: { HOME: "/home/bob", XDG_DATA_HOME: "/data/bob", XDG_RUNTIME_DIR: "/run/user/1000" },
      dataDir: "/data/bob/agent-vault",
      runtimeDir: "/run/user/1000/agent-vault",
      backupsDir: "/data/bob/agent-vault/backups",
      dbFile: "/data/bob/agent-vault/vault.db",
    },
    {
      name: "linux XDG defaults, no runtime dir",
      platform: "linux",
      env: { HOME: "/home/bob" },
      dataDir: "/home/bob/.local/share/agent-vault",
      runtimeDir: "/home/bob/.local/share/agent-vault/run",
      backupsDir: "/home/bob/.local/share/agent-vault/backups",
      dbFile: "/home/bob/.local/share/agent-vault/vault.db",
    },
    {
      name: "linux empty XDG vars count as unset",
      platform: "linux",
      env: { HOME: "/home/bob", XDG_DATA_HOME: "", XDG_RUNTIME_DIR: "" },
      dataDir: "/home/bob/.local/share/agent-vault",
      runtimeDir: "/home/bob/.local/share/agent-vault/run",
      backupsDir: "/home/bob/.local/share/agent-vault/backups",
      dbFile: "/home/bob/.local/share/agent-vault/vault.db",
    },
    {
      name: "linux relative XDG vars are ignored (XDG spec)",
      platform: "linux",
      env: { HOME: "/home/bob", XDG_DATA_HOME: "rel/data", XDG_RUNTIME_DIR: "rel/run" },
      dataDir: "/home/bob/.local/share/agent-vault",
      runtimeDir: "/home/bob/.local/share/agent-vault/run",
      backupsDir: "/home/bob/.local/share/agent-vault/backups",
      dbFile: "/home/bob/.local/share/agent-vault/vault.db",
    },
    {
      name: "win32 LOCALAPPDATA",
      platform: "win32",
      env: { LOCALAPPDATA: "C:\\Users\\Carol\\AppData\\Local", USERPROFILE: "C:\\Users\\Carol" },
      dataDir: "C:\\Users\\Carol\\AppData\\Local\\agent-vault",
      runtimeDir: "C:\\Users\\Carol\\AppData\\Local\\agent-vault\\run",
      backupsDir: "C:\\Users\\Carol\\AppData\\Local\\agent-vault\\backups",
      dbFile: "C:\\Users\\Carol\\AppData\\Local\\agent-vault\\vault.db",
    },
    {
      name: "win32 without LOCALAPPDATA falls back to USERPROFILE",
      platform: "win32",
      env: { USERPROFILE: "C:\\Users\\Carol" },
      dataDir: "C:\\Users\\Carol\\AppData\\Local\\agent-vault",
      runtimeDir: "C:\\Users\\Carol\\AppData\\Local\\agent-vault\\run",
      backupsDir: "C:\\Users\\Carol\\AppData\\Local\\agent-vault\\backups",
      dbFile: "C:\\Users\\Carol\\AppData\\Local\\agent-vault\\vault.db",
    },
  ];

  test.each(cases)("$name", ({ name: _name, platform, env, ...expected }) => {
    expect(getPaths(env, platform)).toEqual(expected);
  });

  describe("AGENT_VAULT_HOME", () => {
    test("darwin", () => {
      expect(getPaths({ HOME: "/Users/a", AGENT_VAULT_HOME: "/tmp/av" }, "darwin")).toEqual({
        dataDir: "/tmp/av",
        runtimeDir: "/tmp/av/run",
        backupsDir: "/tmp/av/backups",
        dbFile: "/tmp/av/vault.db",
      });
    });

    test("linux: runtimeDir follows the override, even when XDG_RUNTIME_DIR is set", () => {
      // sandbox rule: a test that sets AGENT_VAULT_HOME must not reach the real /run/user/<uid>
      expect(
        getPaths(
          { HOME: "/h", AGENT_VAULT_HOME: "/tmp/av", XDG_RUNTIME_DIR: "/run/user/1000" },
          "linux",
        ),
      ).toEqual({
        dataDir: "/tmp/av",
        runtimeDir: "/tmp/av/run",
        backupsDir: "/tmp/av/backups",
        dbFile: "/tmp/av/vault.db",
      });
    });

    test("win32", () => {
      expect(getPaths({ LOCALAPPDATA: "C:\\L", AGENT_VAULT_HOME: "D:\\av" }, "win32")).toEqual({
        dataDir: "D:\\av",
        runtimeDir: "D:\\av\\run",
        backupsDir: "D:\\av\\backups",
        dbFile: "D:\\av\\vault.db",
      });
    });

    test("empty value is ignored", () => {
      expect(getPaths({ HOME: "/h", AGENT_VAULT_HOME: "" }, "linux").dataDir).toBe(
        "/h/.local/share/agent-vault",
      );
    });
  });

  test("does not mutate or read process.env when env is injected", () => {
    const before = JSON.stringify(process.env);
    getPaths({ HOME: "/h" }, "linux");
    expect(JSON.stringify(process.env)).toBe(before);
  });
});
