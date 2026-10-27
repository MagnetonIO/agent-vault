// Windows only. Q3: loopback TCP + mutual token handshake + token file locked with icacls,
// including port squatting in both orders.
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import {
  attack,
  createMutualServer,
  echoLines,
  ev,
  exchange,
  hasOtherUser,
  IDENTITY_ERROR,
  indent,
  mutualConnect,
  newToken,
  PUBLIC,
  preparePublic,
  readOr,
  run,
  runAsOther,
  section,
  sleep,
  tryListen,
  waitForLine,
} from "./lib.mjs";

if (process.platform !== "win32") throw new Error("win-tcp.mjs is Windows only");

const USER = process.env.USERNAME ?? os.userInfo().username;
const failures = [];
const expect = (id, cond, detail) => {
  ev(id, `${cond ? "PASS" : "FAIL"} ${detail}`);
  if (!cond) failures.push(id);
};

const icacls = async (target) => (await run("icacls", [target])).stdout;

/** Principals listed by `icacls <target>` (one per ACE line, after the target path is removed). */
function principals(out, target) {
  return out
    .replaceAll(target, "")
    .split(/\r?\n/)
    .map((l) => /^(.+?):\(/.exec(l.trim())?.[1])
    .filter(Boolean);
}

const isOnlyUser = (names) =>
  names.length === 1 && names[0].toLowerCase().endsWith(USER.toLowerCase());

async function icaclsRun(args) {
  const r = await run("icacls", args);
  console.log(`  $ icacls ${args.map((a) => `"${a}"`).join(" ")}\n${indent(r.stdout + r.stderr)}`);
  return r;
}

/**
 * Lock a directory to the current user. The exact three commands later tasks must reuse.
 * Step 1 alone leaves SYSTEM and Administrators: on a new dir they are explicit ACEs (no `(I)`
 * in the listing), and `/inheritance:r` only removes inherited ones. SIDs, not localized names.
 */
async function lockDir(dir, label) {
  await icaclsRun([dir, "/inheritance:r", "/grant:r", `${USER}:(OI)(CI)F`]);
  const afterStep1 = principals(await icacls(dir), dir);
  ev(`icacls-${label}-after-step1`, JSON.stringify(afterStep1));
  await icaclsRun([dir, "/remove", "*S-1-5-18"]);
  await icaclsRun([dir, "/remove", "*S-1-5-32-544"]);
  const final = principals(await icacls(dir), dir);
  ev(`icacls-${label}-after-step3`, JSON.stringify(final));
  console.log(`icacls AFTER (${label} dir):`);
  console.log(indent(await icacls(dir)));
  expect(`icacls-${label}-dir-only-current-user`, isOnlyUser(final), JSON.stringify(final));
}

async function lockFile(file, label) {
  await icaclsRun([file, "/inheritance:r", "/grant:r", `${USER}:F`]);
  const final = principals(await icacls(file), file);
  expect(`icacls-${label}-file-only-current-user`, isOnlyUser(final), JSON.stringify(final));
}

await preparePublic();
const other = hasOtherUser();
console.log(`node ${process.version}; user=${USER}; second user available: ${other}`);

// ---- the real location: %LOCALAPPDATA%\agent-vault-spike\run (real code: ...\agent-vault\run) --
section("Q3a: token file under %LOCALAPPDATA% with icacls");
const runDir = path.join(process.env.LOCALAPPDATA, "agent-vault-spike", "run");
fs.mkdirSync(runDir, { recursive: true });
console.log("icacls BEFORE (dir, as created by mkdir):");
console.log(indent(await icacls(runDir)));
await lockDir(runDir, "localappdata");

const token = newToken();
const endpointFile = path.join(runDir, "endpoint.json");
const server = createMutualServer(token, echoLines);
const l = await tryListen(server, { host: "127.0.0.1", port: 0 });
expect("tcp-listen", l.ok, l.ok ? "" : `${l.code}`);
const port = server.address().port;
ev("tcp-listen-address", JSON.stringify(server.address()));

const tmp = `${endpointFile}.tmp`; // temp + rename: a reader never sees a half-written file
fs.writeFileSync(tmp, `${JSON.stringify({ host: "127.0.0.1", port, token })}\n`);
fs.renameSync(tmp, endpointFile);
await lockFile(endpointFile, "localappdata");
console.log("icacls AFTER (token file):");
console.log(indent(await icacls(endpointFile)));
const back = JSON.parse(fs.readFileSync(endpointFile, "utf8"));
expect("token-file-readable-by-owner", back.token === token && back.port === port, "");

// ---- handshake ------------------------------------------------------------------------------
section("Q3b: mutual handshake");
const target = { host: "127.0.0.1", port };
const rpc = '{"jsonrpc":"2.0","id":1,"method":"ping"}\n';
const nothing = (r) => r.afterReply === "" && r.serverClosed;

const good = await mutualConnect(target, token, { payload: rpc });
ev("tcp-good-client", JSON.stringify(good));
expect(
  "tcp-good-client-accepted",
  good.ok && good.data.includes('"echo"'),
  "mutual ok + JSON-RPC echo",
);

const wrongTok = await mutualConnect(target, newToken(), { payload: rpc });
ev("tcp-client-with-wrong-token", JSON.stringify(wrongTok));
expect(
  "tcp-client-wrong-token-fails-identity",
  !wrongTok.ok && wrongTok.error === IDENTITY_ERROR && wrongTok.payloadBytesSent === 0,
  "client aborts at the server mac, 0 payload bytes",
);

const bogus = await attack(target, "bogus");
ev("tcp-attacker-bogus-mac", JSON.stringify(bogus));
expect("tcp-attacker-bogus-mac-rejected", nothing(bogus), "closed, no bytes after reply");

const reflect = await attack(target, "reflect");
ev("tcp-attacker-reflect-mac", JSON.stringify(reflect));
expect(
  "tcp-attacker-reflect-rejected",
  nothing(reflect),
  "server mac replayed as client mac: closed",
);

const rpcFirst = await exchange(target, [rpc]);
expect(
  "tcp-rpc-without-handshake-rejected",
  rpcFirst.data === "" && rpcFirst.serverClosed,
  "closed",
);
const shortNonce = await exchange(target, [`${"0".repeat(63)}\n`]);
expect("tcp-short-nonce-rejected", shortNonce.data === "" && shortNonce.serverClosed, "closed");
const silent = await exchange(target, [], 3000);
expect(
  "tcp-silent-client-closed",
  silent.data === "" && silent.serverClosed,
  "closed by 1500ms timer",
);
const flood = await exchange(target, ["A".repeat(4096)]);
expect(
  "tcp-no-newline-flood-closed",
  flood.data === "" && flood.serverClosed,
  "closed at 128 bytes",
);

// ---- cross-user: control vs restricted, under C:\Users\Public (traversable by everyone) -----
section("Q3c: second user vs control file, restricted file, TCP port");
if (other) {
  const ctlDir = path.join(PUBLIC, "ctl");
  const resDir = path.join(PUBLIC, "run");
  fs.mkdirSync(ctlDir, { recursive: true });
  fs.mkdirSync(resDir, { recursive: true });
  const ctlFile = path.join(ctlDir, "endpoint.json");
  const resFile = path.join(resDir, "endpoint.json");
  await lockDir(resDir, "public");
  fs.writeFileSync(ctlFile, `${JSON.stringify({ port, token })}\n`);
  fs.writeFileSync(resFile, `${JSON.stringify({ port, token })}\n`);
  await lockFile(resFile, "public");
  console.log("control file ACL (default, inherited from Public\\av-spike):");
  console.log(indent(await icacls(ctlFile)));

  const f = path.join(PUBLIC, "probe-tcp.txt");
  await runAsOther(
    "probe.ps1",
    ["-ControlFile", ctlFile, "-TokenFile", resFile, "-Port", String(port)],
    f,
  );
  const t = await waitForLine(f, /tcp-wrong-token/, 25000);
  console.log(indent(t + readOr(`${f}.err`)));
  const line = (n) => t.split(/\r?\n/).find((x) => x.startsWith(`PROBE ${n}`)) ?? "(no output)";
  ev("other-user-control-file", line("read-control-file"));
  ev("other-user-restricted-file", line("read-token-file"));
  ev("other-user-tcp-port", line("tcp-wrong-token"));
  ev("other-user-netstat", line("netstat"));
  expect(
    "other-user-control-readable",
    /READ OK/.test(line("read-control-file")),
    "control proves the test discriminates",
  );
  expect(
    "other-user-restricted-denied",
    /DENIED/.test(line("read-token-file")),
    "icacls restriction holds",
  );
  ev(
    "other-user-port-reachable",
    /TCP connected/.test(line("tcp-wrong-token")) ? "yes (handshake required)" : "no",
  );
} else {
  ev("other-user", "SKIPPED (no second user)");
}

// ---- Q3d order A: vaultd listens, someone else tries to bind the same port ------------------
section("Q3d order A: vaultd listening, squatter binds the same 127.0.0.1:port");
{
  const sq = net.createServer();
  const r = await tryListen(sq, { host: "127.0.0.1", port });
  ev("tcp-A-node-second-bind-same-user", r.ok ? "SUCCEEDED (shared!)" : `${r.code}`);
  if (r.ok) sq.close();

  const variants = [["same-user-reuse", false, true]];
  if (other) variants.push(["other-user-plain", true, false], ["other-user-reuse", true, true]);
  for (const [name, asOther, reuse] of variants) {
    const f = path.join(PUBLIC, `squat-tcp-a-${name}.txt`);
    const args = ["-Port", String(port), "-HoldSeconds", "12", ...(reuse ? ["-Reuse"] : [])];
    if (asOther) {
      await runAsOther("squat-tcp.ps1", args, f, { wait: false });
    } else {
      fs.rmSync(f, { force: true });
      spawn(
        "powershell.exe",
        [
          "-NoProfile",
          "-ExecutionPolicy",
          "Bypass",
          "-File",
          path.join(PUBLIC, "squat-tcp.ps1"),
          ...args,
        ],
        {
          stdio: ["ignore", fs.openSync(f, "w"), fs.openSync(`${f}.err`, "w")],
          windowsHide: true,
        },
      );
    }
    const bind = await waitForLine(f, /SQUATTCP (bound|bind FAILED)/, 20000);
    const bindLine = bind.split(/\r?\n/).find((x) => x.startsWith("SQUATTCP")) ?? "no output";
    ev(`tcp-A-${name}-bind`, bindLine);
    if (/bound/.test(bindLine)) {
      const results = [];
      for (let i = 0; i < 6; i++) {
        const c = await mutualConnect(target, token, { payload: rpc });
        results.push(c.ok ? "vaultd" : `refused(${c.error}, payloadBytes=${c.payloadBytesSent})`);
      }
      ev(`tcp-A-${name}-cli-routing`, results.join("; "));
      expect(
        `tcp-A-${name}-no-payload-to-squatter`,
        results.every((x) => x === "vaultd" || /payloadBytes=0\)/.test(x)),
        "every attempt reached vaultd or was refused with 0 payload bytes",
      );
      const log = await waitForLine(f, /SQUATTCP done/, 25000);
      const clientLines = log.split(/\r?\n/).filter((x) => /client=/.test(x));
      ev(
        `tcp-A-${name}-squatter-saw`,
        clientLines.join(" | ") || "no clients reached the squatter",
      );
      expect(
        `tcp-A-${name}-squatter-got-only-nonce`,
        clientLines.every((x) => /after=0/.test(x)),
        "squatter received nothing after its fake reply",
      );
    }
    await sleep(1000);
  }
}

// ---- Q3e order B: stale endpoint.json names a port a squatter now holds ---------------------
section("Q3e order B: vaultd gone, squatter holds the port named by the stale endpoint.json");
{
  await new Promise((r) => server.close(r));
  const stale = JSON.parse(fs.readFileSync(endpointFile, "utf8"));
  const secret =
    '{"jsonrpc":"2.0","id":1,"method":"store","params":{"value":"TOP-SECRET-VALUE"}}\n';
  const cli = () =>
    mutualConnect({ host: stale.host, port: stale.port }, stale.token, { payload: secret });

  for (const [name, reply] of [
    ["node-says-ok", "ok\n"],
    ["node-fake-mac", `${"a".repeat(64)} ${"b".repeat(64)}\n`],
  ]) {
    let received = Buffer.alloc(0);
    const sq = net.createServer((s) => {
      s.on("error", () => {});
      s.on("data", (d) => {
        received = Buffer.concat([received, d]);
        if (received.length === d.length) s.write(reply);
      });
    });
    const r = await tryListen(sq, { host: "127.0.0.1", port: stale.port });
    expect(`tcp-B-${name}-bind`, r.ok, r.ok ? "squatter bound the stale port" : `${r.code}`);
    if (!r.ok) {
      sq.close();
      continue;
    }
    const c = await cli();
    ev(`tcp-B-${name}-cli`, JSON.stringify(c));
    ev(`tcp-B-${name}-squatter-received`, `${received.length} bytes`);
    expect(
      `tcp-B-${name}-refused`,
      !c.ok && /identity check failed/.test(c.error) && c.payloadBytesSent === 0,
      `cli error="${c.error}", payload bytes sent=${c.payloadBytesSent}`,
    );
    expect(
      `tcp-B-${name}-squatter-got-only-nonce`,
      received.length === 65 && !received.toString().includes("TOP-SECRET"),
      `squatter received ${received.length} bytes (a 64-hex nonce + newline is 65)`,
    );
    await new Promise((res) => sq.close(res));
  }

  if (other) {
    const f = path.join(PUBLIC, "squat-tcp-b-other.txt");
    await runAsOther("squat-tcp.ps1", ["-Port", String(stale.port), "-HoldSeconds", "10"], f, {
      wait: false,
    });
    const bindLine =
      (await waitForLine(f, /SQUATTCP (bound|bind FAILED)/, 20000))
        .split(/\r?\n/)
        .find((x) => x.startsWith("SQUATTCP")) ?? "no output";
    ev("tcp-B-other-user-bind", bindLine);
    if (/bound/.test(bindLine)) {
      const c = await cli();
      ev("tcp-B-other-user-cli", JSON.stringify(c));
      expect(
        "tcp-B-other-user-refused",
        !c.ok && /identity check failed/.test(c.error) && c.payloadBytesSent === 0,
        `payload bytes sent=${c.payloadBytesSent}`,
      );
      const log = await waitForLine(f, /SQUATTCP done/, 20000);
      const lines = log.split(/\r?\n/).filter((x) => /client=/.test(x));
      ev("tcp-B-other-user-squatter-saw", lines.join(" | ") || "none");
      expect(
        "tcp-B-other-user-squatter-got-only-nonce",
        lines.length > 0 && lines.every((x) => /first=65 after=0/.test(x)),
        "first=65 (nonce line), after=0",
      );
    }
  } else {
    ev("tcp-B-other-user", "SKIPPED (no second user)");
  }
}

fs.rmSync(runDir, { recursive: true, force: true });
if (failures.length) {
  console.log(`\nFAILED: ${failures.join(", ")}`);
  process.exit(1);
}
console.log("\nTCP OK");
process.exit(0);
