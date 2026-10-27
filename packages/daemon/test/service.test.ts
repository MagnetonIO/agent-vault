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
import {
  createArgv,
  deleteArgv,
  encodeTaskXml,
  queryArgv,
  quoteCommand,
  renderTaskXml,
  schtasksExe,
} from "../src/service/schtasks.js";
import {
  activateArgvs,
  reloadArgv,
  renderUnit,
  deactivateArgv as systemdDeactivate,
  unitPath,
} from "../src/service/systemd.js";

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
    expect(deactivateArgv(501)).toMatchInlineSnapshot(`
      [
        "/bin/launchctl",
        "bootout",
        "gui/501/com.agent-vault.daemon",
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
        argv: ["/opt/my node/node", "/opt/100%/$main.js", "daemon", "run"],
        vaultHome: "/home/me/vault $dir",
      }),
    ).toMatchInlineSnapshot(`
      "[Unit]
      Description=agent-vault daemon (vaultd)

      [Service]
      Type=simple
      ExecStart="/opt/my node/node" /opt/100%%/$$main.js daemon run
      Restart=on-failure
      Environment="AGENT_VAULT_HOME=/home/me/vault $dir"

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
    expect(systemdDeactivate()).toMatchInlineSnapshot(`
      [
        "systemctl",
        "--user",
        "disable",
        "--now",
        "agent-vault.service",
      ]
    `);
    expect(reloadArgv()).toEqual(["systemctl", "--user", "daemon-reload"]);
  });
});

describe("schtasks", () => {
  it("quotes only what needs it", () => {
    expect(quoteCommand(WIN_ARGV.slice(1))).toMatchInlineSnapshot(
      `"C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\agent-vault\\dist\\main.js daemon run"`,
    );
    expect(quoteCommand(["C:\\a\\b.exe", "daemon", "run"])).toBe("C:\\a\\b.exe daemon run");
  });

  it("task XML: no 72 h limit, runs on battery, restarts, current user, least privilege", () => {
    expect(renderTaskXml({ argv: WIN_ARGV, user: "LAPTOP\\me" })).toMatchInlineSnapshot(`
      "<?xml version="1.0" encoding="UTF-16"?>
      <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
        <RegistrationInfo>
          <Description>agent-vault daemon (vaultd)</Description>
        </RegistrationInfo>
        <Triggers>
          <LogonTrigger>
            <Enabled>true</Enabled>
            <UserId>LAPTOP\\me</UserId>
          </LogonTrigger>
        </Triggers>
        <Principals>
          <Principal id="Author">
            <UserId>LAPTOP\\me</UserId>
            <LogonType>InteractiveToken</LogonType>
            <RunLevel>LeastPrivilege</RunLevel>
          </Principal>
        </Principals>
        <Settings>
          <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
          <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
          <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
          <AllowHardTerminate>true</AllowHardTerminate>
          <StartWhenAvailable>false</StartWhenAvailable>
          <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
          <AllowStartOnDemand>true</AllowStartOnDemand>
          <Enabled>true</Enabled>
          <Hidden>false</Hidden>
          <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
          <Priority>7</Priority>
          <RestartOnFailure>
            <Interval>PT1M</Interval>
            <Count>3</Count>
          </RestartOnFailure>
        </Settings>
        <Actions Context="Author">
          <Exec>
            <Command>C:\\Program Files\\nodejs\\node.exe</Command>
            <Arguments>C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\agent-vault\\dist\\main.js daemon run</Arguments>
          </Exec>
        </Actions>
      </Task>
      "
    `);
  });

  it("escapes the user, the command and the arguments", () => {
    const xml = renderTaskXml({
      argv: ["C:\\R&D\\<n>\\node.exe", 'C:\\it\'s "x"\\main.js', "daemon", "run"],
      user: "A&B\\o'neil",
    });
    expect(xml).toContain("<Command>C:\\R&amp;D\\&lt;n&gt;\\node.exe</Command>");
    expect(xml).toContain("<UserId>A&amp;B\\o&apos;neil</UserId>");
    expect(xml).toContain(
      "<Arguments>&quot;C:\\it&apos;s \\&quot;x\\&quot;\\main.js&quot; daemon run</Arguments>",
    );
  });

  it("is UTF-16 LE with a byte order mark", () => {
    const buf = encodeTaskXml("<a/>é");
    expect([...buf.subarray(0, 2)]).toEqual([0xff, 0xfe]);
    expect(buf.subarray(2).toString("utf16le")).toBe("<a/>é");
  });

  it("create, query and delete argv", () => {
    const exe = schtasksExe({ SystemRoot: "C:\\Windows" });
    expect(exe).toBe("C:\\Windows\\System32\\schtasks.exe");
    expect(createArgv(exe, "C:\\v\\task.xml")).toMatchInlineSnapshot(`
      [
        "C:\\Windows\\System32\\schtasks.exe",
        "/Create",
        "/TN",
        "agent-vault-daemon",
        "/XML",
        "C:\\v\\task.xml",
        "/F",
      ]
    `);
    expect(queryArgv(exe)).toMatchInlineSnapshot(`
      [
        "C:\\Windows\\System32\\schtasks.exe",
        "/Query",
        "/TN",
        "agent-vault-daemon",
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

/**
 * Records every command and never runs one: no test may reach launchctl, systemctl or schtasks.
 * `code` decides each exit code; `xml` collects the task definition at the moment schtasks would
 * read it (the file is gone afterwards).
 */
function recorder(code: number | ((argv: Call) => number) = 0): {
  run: CommandRunner;
  calls: Call[];
  xml: string[];
} {
  const calls: Call[] = [];
  const xml: string[] = [];
  return {
    calls,
    xml,
    run: async (argv) => {
      calls.push(argv);
      const i = argv.indexOf("/XML");
      if (i >= 0)
        xml.push(
          fs
            .readFileSync(argv[i + 1] as string)
            .subarray(2) // the byte order mark
            .toString("utf16le"),
        );
      const c = typeof code === "function" ? code(argv) : code;
      return { code: c, stderr: c === 0 ? "" : "boom" };
    },
  };
}

const LAUNCHCTL = "/bin/launchctl";
const LABEL_TARGET = "gui/501/com.agent-vault.daemon";

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
      expect(result.notes).toEqual([
        "The service pins /usr/local/bin/node; reinstall after upgrading Node.",
      ]);
      const text = fs.readFileSync(plist, "utf8");
      expect(text).toContain(path.join(home, "vault", "logs", "vaultd.log"));
      expect(text).toContain("<key>AGENT_VAULT_HOME</key>");
      expect(fs.existsSync(path.join(home, "vault", "logs"))).toBe(true);
      expect(calls).toEqual([
        [LAUNCHCTL, "bootout", LABEL_TARGET],
        [LAUNCHCTL, "bootstrap", "gui/501", plist],
      ]);

      calls.length = 0;
      const gone = await uninstallService(opts);
      expect(gone).toMatchObject({ installed: true, warnings: [] });
      expect(fs.existsSync(plist)).toBe(false);
      expect(calls).toEqual([[LAUNCHCTL, "bootout", LABEL_TARGET]]);
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

    it("unloads by label even when the plist was deleted by hand", async () => {
      const { run, calls } = recorder();
      const result = await uninstallService({ ...base(), platform: "darwin", run });
      expect(calls).toEqual([[LAUNCHCTL, "bootout", LABEL_TARGET]]);
      expect(result).toMatchObject({ installed: true, warnings: [] });
    });

    it("says not installed, quietly, when there is no plist and nothing is loaded", async () => {
      const { run } = recorder(113);
      const result = await uninstallService({ ...base(), platform: "darwin", run });
      expect(result).toMatchObject({ installed: false, warnings: [] });
    });
  });

  describe.skipIf(process.platform === "win32")("Linux", () => {
    const unitFile = () => path.join(home, ".config", "systemd", "user", "agent-vault.service");
    const DISABLE = ["systemctl", "--user", "disable", "--now", "agent-vault.service"];
    const RELOAD = ["systemctl", "--user", "daemon-reload"];
    const ENABLE = ["systemctl", "--user", "enable", "--now", "agent-vault.service"];

    it("writes the unit, enables it, and uninstall puts everything back", async () => {
      const { run, calls } = recorder();
      const opts = { ...base(), platform: "linux" as const, run };

      const result = await installService(opts);
      expect(result.unitFile).toBe(unitFile());
      expect(fs.readFileSync(unitFile(), "utf8")).toContain("Restart=on-failure");
      expect(calls).toEqual([RELOAD, ENABLE]);

      // Stop and disable, delete the unit, and only then reload.
      calls.length = 0;
      const seen: boolean[] = [];
      const watched = recorder();
      const watch: CommandRunner = async (argv) => {
        seen.push(fs.existsSync(unitFile()));
        return watched.run(argv);
      };
      await uninstallService({ ...opts, run: watch });
      expect(fs.existsSync(unitFile())).toBe(false);
      expect(watched.calls).toEqual([DISABLE, RELOAD]);
      expect(seen).toEqual([true, false]);
    });

    it("disables the unit again when `enable --now` fails, before deleting it", async () => {
      const { run, calls } = recorder((argv) => (argv.includes("enable") ? 1 : 0));
      await expect(installService({ ...base(), platform: "linux", run })).rejects.toThrow(
        /enable.*boom/s,
      );
      expect(calls).toEqual([RELOAD, ENABLE, DISABLE, RELOAD]);
      expect(fs.existsSync(unitFile())).toBe(false);
    });

    it("says not installed, quietly, when there is no unit and nothing to disable", async () => {
      const { run, calls } = recorder(1);
      const result = await uninstallService({ ...base(), platform: "linux", run });
      expect(result).toMatchObject({ installed: false, warnings: [] });
      expect(calls).toEqual([DISABLE]);
    });

    it("warns, and still deletes the unit, when disabling an existing unit fails", async () => {
      await installService({ ...base(), platform: "linux", run: recorder().run });
      const { run } = recorder((argv) => (argv.includes("disable") ? 1 : 0));
      const result = await uninstallService({ ...base(), platform: "linux", run });
      expect(result.installed).toBe(true);
      expect(result.warnings.join("\n")).toMatch(/disable.*boom/s);
      expect(fs.existsSync(unitFile())).toBe(false);
    });
  });

  describe("Windows", () => {
    // paths are injected so nothing is written outside the temp home, whatever the host.
    const win = () => ({
      ...base(),
      platform: "win32" as const,
      argv: WIN_ARGV,
      user: "LAPTOP\\me",
      env: { SystemRoot: "C:\\Windows" } as NodeJS.ProcessEnv,
      paths: {
        dataDir: path.join(home, "vault"),
        runtimeDir: path.join(home, "vault", "run"),
        backupsDir: path.join(home, "vault", "backups"),
        dbFile: path.join(home, "vault", "vault.db"),
      },
    });
    const exe = "C:\\Windows\\System32\\schtasks.exe";

    it("registers the task from a temp XML file that is gone afterwards, and removes it", async () => {
      const { run, calls, xml } = recorder();
      const result = await installService({ ...win(), run });
      expect(result.unitFile).toBeUndefined();
      expect(calls).toHaveLength(1);
      const create = calls[0] as string[];
      expect(create.slice(0, 5)).toEqual(createArgv(exe, "").slice(0, 5));
      expect(create.at(-1)).toBe("/F");
      const xmlFile = create[create.indexOf("/XML") + 1] as string;
      expect(path.dirname(xmlFile)).toBe(path.join(home, "vault"));
      expect(fs.existsSync(xmlFile)).toBe(false);
      expect(xml[0]).toBe(renderTaskXml({ argv: WIN_ARGV, user: "LAPTOP\\me" }));
      expect(result.notes).toEqual([
        "The service pins C:\\Program Files\\nodejs\\node.exe; reinstall after upgrading Node.",
      ]);

      calls.length = 0;
      const gone = await uninstallService({ ...win(), run });
      expect(calls).toEqual([queryArgv(exe), deleteArgv(exe)]);
      expect(gone).toMatchObject({ installed: true, warnings: [] });
    });

    it("removes the temp XML file when schtasks fails", async () => {
      const { run } = recorder(1);
      await expect(installService({ ...win(), run })).rejects.toThrow(/boom/);
      expect(fs.readdirSync(path.join(home, "vault"))).toEqual([]);
    });

    it("says not installed, quietly, when the task does not exist", async () => {
      const { run, calls } = recorder(1);
      const result = await uninstallService({ ...win(), run });
      expect(result).toMatchObject({ installed: false, warnings: [] });
      expect(calls).toEqual([queryArgv(exe)]);
    });

    it("cannot carry AGENT_VAULT_HOME into the task", async () => {
      const { run, calls } = recorder();
      const env = { SystemRoot: "C:\\Windows", AGENT_VAULT_HOME: "C:\\v" };
      await expect(installService({ ...win(), env, run })).rejects.toThrow(/AGENT_VAULT_HOME/);
      expect(calls).toEqual([]);
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
      "with the passphrase set it proceeds, warns that the service cannot use it, and never writes it",
      async () => {
        const { run } = recorder();
        const env: NodeJS.ProcessEnv = {
          HOME: home,
          AGENT_VAULT_KEYFILE_PASSPHRASE: "hunter2 hunter2",
        };
        const result = await installService({
          ...base(),
          env,
          keystore: "keyfile",
          platform: "linux",
          run,
        });
        expect(fs.readFileSync(unitPath(home), "utf8")).not.toContain("hunter2");
        expect(result.warnings).toHaveLength(1);
        expect(result.warnings[0]).toMatch(/^WARNING: .*daemon cannot unlock the keyfile store/);
        expect(result.warnings[0]).not.toContain("hunter2");
      },
    );

    it.skipIf(process.platform === "win32")("the os store gets no warning", async () => {
      const { run } = recorder();
      const result = await installService({ ...base(), platform: "linux", run });
      expect(result.warnings).toEqual([]);
    });
  });
});
