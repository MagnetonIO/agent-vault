import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { daemonRunArgv } from "../src/autostart.js";
import {
  type CommandRunner,
  installService,
  ServiceError,
  uninstallService,
} from "../src/service/index.js";
import { activateArgv, deactivateArgv, plistPath, renderPlist } from "../src/service/launchd.js";
import { createArgv, deleteArgv, quoteCommand, schtasksExe } from "../src/service/schtasks.js";
import { activateArgvs, deactivateArgvs, renderUnit, unitPath } from "../src/service/systemd.js";

const NODE_ARGV = [
  "/usr/local/bin/node",
  "/usr/local/lib/node_modules/agent-vault/dist/main.js",
  "daemon",
  "run",
];
const WIN_ARGV = [
  "C:\\Program Files\\nodejs\\node.exe",
  "C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\agent-vault\\dist\\main.js",
  "daemon",
  "run",
];

describe("launchd", () => {
  it("plist", () => {
    expect(
      renderPlist({
        argv: NODE_ARGV,
        logFile: "/Users/me/Library/Application Support/agent-vault/logs/vaultd.log",
        vaultHome: undefined,
      }),
    ).toMatchInlineSnapshot(`
      "<?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <dict>
        <key>Label</key>
        <string>com.agent-vault.daemon</string>
        <key>ProgramArguments</key>
        <array>
          <string>/usr/local/bin/node</string>
          <string>/usr/local/lib/node_modules/agent-vault/dist/main.js</string>
          <string>daemon</string>
          <string>run</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <dict>
          <key>SuccessfulExit</key>
          <false/>
        </dict>
        <key>StandardOutPath</key>
        <string>/Users/me/Library/Application Support/agent-vault/logs/vaultd.log</string>
        <key>StandardErrorPath</key>
        <string>/Users/me/Library/Application Support/agent-vault/logs/vaultd.log</string>
      </dict>
      </plist>
      "
    `);
  });

  it("plist with AGENT_VAULT_HOME, escaped", () => {
    expect(
      renderPlist({
        argv: ["/opt/a&b/node", "/opt/<x>/main.js", "daemon", "run"],
        logFile: "/v/logs/vaultd.log",
        vaultHome: "/v & <home>",
      }),
    ).toMatchInlineSnapshot(`
      "<?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <dict>
        <key>Label</key>
        <string>com.agent-vault.daemon</string>
        <key>ProgramArguments</key>
        <array>
          <string>/opt/a&amp;b/node</string>
          <string>/opt/&lt;x&gt;/main.js</string>
          <string>daemon</string>
          <string>run</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
        <key>KeepAlive</key>
        <dict>
          <key>SuccessfulExit</key>
          <false/>
        </dict>
        <key>StandardOutPath</key>
        <string>/v/logs/vaultd.log</string>
        <key>StandardErrorPath</key>
        <string>/v/logs/vaultd.log</string>
        <key>EnvironmentVariables</key>
        <dict>
          <key>AGENT_VAULT_HOME</key>
          <string>/v &amp; &lt;home&gt;</string>
        </dict>
      </dict>
      </plist>
      "
    `);
  });

  it("paths and argv", () => {
    expect(plistPath("/Users/me")).toBe(
      "/Users/me/Library/LaunchAgents/com.agent-vault.daemon.plist",
    );
    expect(activateArgv(501, "/p.plist")).toMatchInlineSnapshot(`
      [
        "/bin/launchctl",
        "bootstrap",
        "gui/501",
        "/p.plist",
      ]
    `);
    expect(deactivateArgv(501, "/p.plist")).toMatchInlineSnapshot(`
      [
        "/bin/launchctl",
        "bootout",
        "gui/501",
        "/p.plist",
      ]
    `);
  });
});

describe("systemd", () => {
  it("unit", () => {
    expect(renderUnit({ argv: NODE_ARGV, vaultHome: undefined })).toMatchInlineSnapshot(`
      "[Unit]
      Description=agent-vault daemon (vaultd)

      [Service]
      Type=simple
      ExecStart=/usr/local/bin/node /usr/local/lib/node_modules/agent-vault/dist/main.js daemon run
      Restart=on-failure

      [Install]
      WantedBy=default.target
      "
    `);
  });

  it("unit with AGENT_VAULT_HOME, quoting", () => {
    expect(
      renderUnit({
        argv: ["/opt/my node/node", "/opt/100%/main.js", "daemon", "run"],
        vaultHome: "/home/me/vault $dir",
      }),
    ).toMatchInlineSnapshot(`
      "[Unit]
      Description=agent-vault daemon (vaultd)

      [Service]
      Type=simple
      ExecStart="/opt/my node/node" /opt/100%%/main.js daemon run
      Restart=on-failure
      Environment="AGENT_VAULT_HOME=/home/me/vault $$dir"

      [Install]
      WantedBy=default.target
      "
    `);
  });

  it("paths and argv", () => {
    expect(unitPath("/home/me")).toBe("/home/me/.config/systemd/user/agent-vault.service");
    expect(activateArgvs()).toMatchInlineSnapshot(`
      [
        [
          "systemctl",
          "--user",
          "daemon-reload",
        ],
        [
          "systemctl",
          "--user",
          "enable",
          "--now",
          "agent-vault.service",
        ],
      ]
    `);
    expect(deactivateArgvs()).toMatchInlineSnapshot(`
      [
        [
          "systemctl",
          "--user",
          "disable",
          "--now",
          "agent-vault.service",
        ],
        [
          "systemctl",
          "--user",
          "daemon-reload",
        ],
      ]
    `);
  });
});

describe("schtasks", () => {
  it("quotes only what needs it", () => {
    expect(quoteCommand(WIN_ARGV)).toMatchInlineSnapshot(
      `""C:\\Program Files\\nodejs\\node.exe" C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\agent-vault\\dist\\main.js daemon run"`,
    );
    expect(quoteCommand(["C:\\a\\b.exe", "daemon", "run"])).toBe("C:\\a\\b.exe daemon run");
  });

  it("create and delete argv", () => {
    const exe = schtasksExe({ SystemRoot: "C:\\Windows" });
    expect(exe).toBe("C:\\Windows\\System32\\schtasks.exe");
    expect(createArgv(exe, WIN_ARGV)).toMatchInlineSnapshot(`
      [
        "C:\\Windows\\System32\\schtasks.exe",
        "/Create",
        "/SC",
        "ONLOGON",
        "/TN",
        "agent-vault-daemon",
        "/TR",
        ""C:\\Program Files\\nodejs\\node.exe" C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\agent-vault\\dist\\main.js daemon run",
        "/RL",
        "LIMITED",
        "/F",
      ]
    `);
    expect(deleteArgv(exe)).toMatchInlineSnapshot(`
      [
        "C:\\Windows\\System32\\schtasks.exe",
        "/Delete",
        "/TN",
        "agent-vault-daemon",
        "/F",
      ]
    `);
  });

  it("refuses a command longer than the 261 characters /TR takes", () => {
    expect(() => createArgv("schtasks.exe", [`C:\\${"a".repeat(300)}`, "daemon", "run"])).toThrow(
      /261/,
    );
  });
});

describe("daemonRunArgv", () => {
  it("is node plus the script, or the SEA binary alone", () => {
    const self = fs.realpathSync(process.execPath);
    expect(daemonRunArgv({ sea: false, execPath: "/n/node", entry: self })).toEqual([
      "/n/node",
      self,
      "daemon",
      "run",
    ]);
    expect(daemonRunArgv({ sea: true, execPath: self, entry: "ignored" })).toEqual([
      self,
      "daemon",
      "run",
    ]);
  });

  it("will not guess without a script", () => {
    expect(() => daemonRunArgv({ sea: false, execPath: "/n/node", entry: undefined })).toThrow(
      /argv\[1\]/,
    );
  });
});

type Call = readonly string[];

/** Records every command and never runs one: no test may reach launchctl, systemctl or schtasks. */
function recorder(code = 0): { run: CommandRunner; calls: Call[] } {
  const calls: Call[] = [];
  return {
    calls,
    run: async (argv) => {
      calls.push(argv);
      return { code, stderr: code === 0 ? "" : "boom" };
    },
  };
}

describe("install and uninstall", () => {
  let home: string;
  beforeEach(() => {
    home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "avs-")));
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  });

  const base = () => ({
    home,
    uid: 501,
    keystore: "os" as const,
    argv: NODE_ARGV,
    env: { HOME: home, AGENT_VAULT_HOME: path.join(home, "vault") } as NodeJS.ProcessEnv,
  });

  describe.skipIf(process.platform === "win32")("macOS", () => {
    it("writes the plist from getPaths, activates, and uninstall puts everything back", async () => {
      const { run, calls } = recorder();
      const opts = { ...base(), platform: "darwin" as const, run };
      const plist = path.join(home, "Library", "LaunchAgents", "com.agent-vault.daemon.plist");

      const result = await installService(opts);
      expect(result.unitFile).toBe(plist);
      const text = fs.readFileSync(plist, "utf8");
      expect(text).toContain(path.join(home, "vault", "logs", "vaultd.log"));
      expect(text).toContain("<key>AGENT_VAULT_HOME</key>");
      expect(fs.existsSync(path.join(home, "vault", "logs"))).toBe(true);
      expect(calls).toEqual([
        ["/bin/launchctl", "bootout", "gui/501", plist],
        ["/bin/launchctl", "bootstrap", "gui/501", plist],
      ]);

      calls.length = 0;
      await uninstallService(opts);
      expect(fs.existsSync(plist)).toBe(false);
      expect(calls).toEqual([["/bin/launchctl", "bootout", "gui/501", plist]]);
    });

    it("takes the log dir from getPaths when AGENT_VAULT_HOME is unset", async () => {
      const { run } = recorder();
      const env: NodeJS.ProcessEnv = { HOME: home };
      await installService({ ...base(), env, platform: "darwin", run });
      const text = fs.readFileSync(plistPath(home), "utf8");
      expect(text).toContain(
        path.join(home, "Library", "Application Support", "agent-vault", "logs", "vaultd.log"),
      );
      expect(text).not.toContain("AGENT_VAULT_HOME");
    });

    it("leaves no unit behind when activation fails", async () => {
      const { run } = recorder(5);
      await expect(installService({ ...base(), platform: "darwin", run })).rejects.toThrow(
        /bootstrap.*boom/s,
      );
      expect(fs.existsSync(plistPath(home))).toBe(false);
    });
  });

  describe.skipIf(process.platform === "win32")("Linux", () => {
    it("writes the unit, enables it, and uninstall puts everything back", async () => {
      const { run, calls } = recorder();
      const opts = { ...base(), platform: "linux" as const, run };
      const unit = path.join(home, ".config", "systemd", "user", "agent-vault.service");

      const result = await installService(opts);
      expect(result.unitFile).toBe(unit);
      expect(fs.readFileSync(unit, "utf8")).toContain("Restart=on-failure");
      expect(calls).toEqual([
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "--now", "agent-vault.service"],
      ]);

      calls.length = 0;
      await uninstallService(opts);
      expect(fs.existsSync(unit)).toBe(false);
      expect(calls).toEqual([
        ["systemctl", "--user", "disable", "--now", "agent-vault.service"],
        ["systemctl", "--user", "daemon-reload"],
      ]);
    });
  });

  describe("Windows", () => {
    const win = () => ({
      ...base(),
      platform: "win32" as const,
      argv: WIN_ARGV,
      env: { SystemRoot: "C:\\Windows" } as NodeJS.ProcessEnv,
    });
    const exe = "C:\\Windows\\System32\\schtasks.exe";

    it("registers and removes the logon task, writing no file", async () => {
      const { run, calls } = recorder();
      const result = await installService({ ...win(), run });
      expect(result.unitFile).toBeUndefined();
      expect(calls).toEqual([createArgv(exe, WIN_ARGV)]);

      calls.length = 0;
      await uninstallService({ ...win(), run });
      expect(calls).toEqual([deleteArgv(exe)]);
    });

    it("cannot carry AGENT_VAULT_HOME into the task", async () => {
      const { run, calls } = recorder();
      const env = { SystemRoot: "C:\\Windows", AGENT_VAULT_HOME: "C:\\v" };
      await expect(installService({ ...win(), env, run })).rejects.toThrow(/AGENT_VAULT_HOME/);
      expect(calls).toEqual([]);
    });
  });

  describe("uninstall when nothing is installed", () => {
    it.skipIf(process.platform === "win32")("still succeeds and says what failed", async () => {
      const { run } = recorder(3);
      const result = await uninstallService({ ...base(), platform: "linux", run });
      expect(result.warnings.join("\n")).toMatch(/disable.*boom/s);
    });
  });

  describe("the keyfile store", () => {
    const refusal =
      "the keyfile store needs a passphrase at daemon start; use --keystore os or set AGENT_VAULT_KEYFILE_PASSPHRASE in the service environment yourself";

    it.each(["darwin", "linux", "win32"] as const)(
      "%s refuses without a passphrase",
      async (platform) => {
        const { run, calls } = recorder();
        const env: NodeJS.ProcessEnv = { SystemRoot: "C:\\Windows", HOME: home };
        const err = await installService({
          ...base(),
          env,
          keystore: "keyfile",
          platform,
          run,
        }).catch((e: unknown) => e);
        expect(err).toBeInstanceOf(ServiceError);
        expect((err as Error).message).toBe(refusal);
        expect(calls).toEqual([]);
        expect(fs.readdirSync(home)).toEqual([]);
      },
    );

    it.skipIf(process.platform === "win32")(
      "proceeds when the passphrase is set, and never writes it into the unit",
      async () => {
        const { run } = recorder();
        const env: NodeJS.ProcessEnv = {
          HOME: home,
          AGENT_VAULT_KEYFILE_PASSPHRASE: "hunter2 hunter2",
        };
        await installService({ ...base(), env, keystore: "keyfile", platform: "linux", run });
        expect(fs.readFileSync(unitPath(home), "utf8")).not.toContain("hunter2");
      },
    );
  });
});
