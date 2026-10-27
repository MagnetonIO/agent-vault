import fs from "node:fs";
import path from "node:path";
import { expect, test } from "vitest";
import { alive, makeSandbox } from "./harness.js";

// Each call starts node, and the first one in a sandbox also starts the daemon.
const TIMEOUT_MS = 60_000;

const put = (file: string, text: string): string => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  return file;
};
const read = (file: string): string => fs.readFileSync(file, "utf8");

test("install, doctor and uninstall for opencode, in a sandbox that never runs opencode", {
  timeout: TIMEOUT_MS,
}, async () => {
  const sb = makeSandbox();
  // PATH holds nothing, so a stray `opencode` call could not start; the config home is ours.
  const empty = path.join(sb.dir, "empty-path");
  fs.mkdirSync(empty, { recursive: true });
  const xdg = path.join(sb.dir, "xdg-config");
  const config = path.join(xdg, "opencode", "opencode.json");
  const run = (args: string[]) =>
    sb.cli(args, { env: { PATH: empty, Path: empty, XDG_CONFIG_HOME: xdg } });

  let pid: number | null = null;
  try {
    const init = await sb.cli(["init", "--keystore", "keyfile"]);
    expect(init.code, init.stderr).toBe(0);
    pid = await sb.daemonPid();

    const original = `{\n  // keep me\n  "theme": "x"\n}\n`;
    put(config, original);

    const installed = await run(["install", "opencode"]);
    expect(installed.code, installed.stderr).toBe(0);
    const entry = (
      JSON.parse(read(config).replace("// keep me", "")) as {
        mcp: Record<string, { type: string; command: string[]; enabled: boolean }>;
      }
    ).mcp["agent-vault"];
    expect(entry).toMatchObject({ type: "local", enabled: true });
    expect(entry?.command.at(-1)).toBe("mcp");
    expect(read(config)).toContain("// keep me");

    const doctor = await run(["doctor", "opencode"]);
    expect(doctor.code, doctor.stdout + doctor.stderr).toBe(0);
    expect(doctor.stdout).not.toContain("FAIL");
    expect(doctor.stdout).toContain("all 3 checks passed");
    expect(doctor.stdout).toContain(
      "info  prompt capture: use agent-vault grab (no OpenCode prompt hook yet)",
    );
    expect(doctor.stdout).toContain(
      "info  note: pasted text is stored in opencode.db, which agent-vault does not scrub; run agent-vault scan to find exposed keys",
    );

    const hook = await sb.cli(["hook", "opencode", "prompt-submit"], {
      stdin: JSON.stringify({ prompt: "anything" }),
      env: { PATH: empty, Path: empty, XDG_CONFIG_HOME: xdg },
    });
    expect(hook).toMatchObject({ code: 0, stdout: "" });

    const removed = await run(["uninstall", "opencode"]);
    expect(removed.code, removed.stderr).toBe(0);
    expect(read(config)).toBe(original);

    const after = await run(["doctor", "opencode"]);
    expect(after.code).toBe(1);
    expect(after.stdout).toMatch(/FAIL\s+mcp/);
    expect(after.stdout).toContain("fix: agent-vault install opencode");

    // A file install made goes away with uninstall.
    fs.rmSync(config);
    expect((await run(["install", "opencode"])).code).toBe(0);
    expect(fs.existsSync(config)).toBe(true);
    expect((await run(["uninstall", "opencode"])).code).toBe(0);
    expect(fs.existsSync(config)).toBe(false);
  } finally {
    await sb.stopDaemon();
    sb.remove();
  }
  if (pid !== null) expect(alive(pid), `vaultd ${pid} is still running`).toBe(false);
});
