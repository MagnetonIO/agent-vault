// Windows only. Q3: loopback TCP + token file locked to the current user with icacls.
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  createTokenServer,
  echoLines,
  ev,
  exchange,
  hasOtherUser,
  indent,
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

/**
 * Restrict `target` to the current user only. Exact commands later tasks must reuse.
 * `/inheritance:r` + `/grant:r` alone left explicit SYSTEM/Administrators ACEs on a directory
 * (see run log), so every other principal icacls still lists is then removed by name.
 */
async function lockDown(target, isDir) {
  const grant = isDir ? `${USER}:(OI)(CI)F` : `${USER}:F`;
  const steps = [[target, "/inheritance:r", "/grant:r", grant]];
  for (const args of steps) {
    const r = await run("icacls", args);
    console.log(
      `  $ icacls ${args.map((a) => `"${a}"`).join(" ")}\n${indent(r.stdout + r.stderr)}`,
    );
  }
  for (const who of principals(await icacls(target), target)) {
    if (who.toLowerCase().endsWith(USER.toLowerCase())) continue;
    const args = [target, "/remove", who];
    const r = await run("icacls", args);
    console.log(
      `  $ icacls ${args.map((a) => `"${a}"`).join(" ")}\n${indent(r.stdout + r.stderr)}`,
    );
  }
}

const icacls = async (target) => (await run("icacls", [target])).stdout;

/** Principals listed by `icacls <target>` (one per ACE line, after the target path is removed). */
function principals(out, target) {
  return out
    .replaceAll(target, "")
    .split(/\r?\n/)
    .map((l) => /^(.+?):\(/.exec(l.trim())?.[1])
    .filter(Boolean);
}

await preparePublic();
const other = hasOtherUser();
console.log(`node ${process.version}; user=${USER}; second user available: ${other}`);

// ---- the real location: %LOCALAPPDATA%\agent-vault-spike\run --------------------------------
section("Q3a: token file under %LOCALAPPDATA% with icacls");
const runDir = path.join(process.env.LOCALAPPDATA, "agent-vault-spike", "run");
fs.mkdirSync(runDir, { recursive: true });
console.log("icacls BEFORE (dir, default inherited ACL):");
console.log(indent(await icacls(runDir)));
await lockDown(runDir, true);
console.log("icacls AFTER (dir):");
const dirAfter = await icacls(runDir);
console.log(indent(dirAfter));

const token = randomBytes(32).toString("hex");
const endpointFile = path.join(runDir, "endpoint.json");

const server = createTokenServer(token, echoLines);
const l = await tryListen(server, { host: "127.0.0.1", port: 0 });
expect("tcp-listen", l.ok, l.ok ? "" : `${l.code}`);
const port = server.address().port;
ev("tcp-listen-address", JSON.stringify(server.address()));

// write via temp + rename so a reader never sees a half-written file
const tmp = `${endpointFile}.tmp`;
fs.writeFileSync(tmp, `${JSON.stringify({ host: "127.0.0.1", port, token })}\n`);
fs.renameSync(tmp, endpointFile);
await lockDown(endpointFile, false);
console.log("icacls AFTER (token file):");
const fileAfter = await icacls(endpointFile);
console.log(indent(fileAfter));

const names = principals(fileAfter, endpointFile);
ev("icacls-file-principals", JSON.stringify(names));
const onlyUser = names.length === 1 && names[0].toLowerCase().endsWith(USER.toLowerCase());
expect("icacls-file-only-current-user", onlyUser, `principals=${JSON.stringify(names)}`);
const dnames = principals(dirAfter, runDir);
expect(
  "icacls-dir-only-current-user",
  dnames.length === 1 && dnames[0].toLowerCase().endsWith(USER.toLowerCase()),
  `principals=${JSON.stringify(dnames)}`,
);
const back = JSON.parse(fs.readFileSync(endpointFile, "utf8"));
expect("token-file-readable-by-owner", back.token === token && back.port === port, "");

// ---- handshake ------------------------------------------------------------------------------
section("Q3b: token handshake");
const target = { host: "127.0.0.1", port };
const rpc = '{"jsonrpc":"2.0","id":1,"method":"ping"}\n';

const good = await exchange(target, [`${token}\n`, rpc]);
ev("tcp-right-token", `data=${JSON.stringify(good.data)} serverClosed=${good.serverClosed}`);
expect(
  "tcp-right-token-accepted",
  good.data.startsWith("ok\n") && good.data.includes('"echo"'),
  "got ok + JSON-RPC echo",
);

const wrong = await exchange(target, [`${"0".repeat(64)}\n`, rpc]);
ev("tcp-wrong-token", `data=${JSON.stringify(wrong.data)} serverClosed=${wrong.serverClosed}`);
expect("tcp-wrong-token-rejected", wrong.data === "" && wrong.serverClosed, "closed, no bytes");

const short = await exchange(target, [`${token.slice(0, 63)}\n`, rpc]);
expect("tcp-short-token-rejected", short.data === "" && short.serverClosed, "closed, no bytes");

const rpcFirst = await exchange(target, [rpc]);
expect("tcp-rpc-without-token-rejected", rpcFirst.data === "" && rpcFirst.serverClosed, "closed");

const silent = await exchange(target, [], 3000);
expect(
  "tcp-silent-client-closed-by-timeout",
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
section("Q3c: second user vs control file and restricted file");
if (other) {
  const ctlDir = path.join(PUBLIC, "ctl");
  const resDir = path.join(PUBLIC, "run");
  fs.mkdirSync(ctlDir, { recursive: true });
  fs.mkdirSync(resDir, { recursive: true });
  const ctlFile = path.join(ctlDir, "endpoint.json");
  const resFile = path.join(resDir, "endpoint.json");
  await lockDown(resDir, true);
  fs.writeFileSync(ctlFile, `${JSON.stringify({ port, token })}\n`);
  fs.writeFileSync(resFile, `${JSON.stringify({ port, token })}\n`);
  await lockDown(resFile, false);
  console.log("control file ACL (default, inherited from Public\\av-spike):");
  console.log(indent(await icacls(ctlFile)));
  console.log("restricted file ACL:");
  console.log(indent(await icacls(resFile)));

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
  // the loopback port itself is reachable by the other user; only the token protects it
  ev(
    "other-user-port-reachable",
    /TCP connected/.test(line("tcp-wrong-token")) ? "yes (token required)" : "no",
  );
} else {
  ev("other-user", "SKIPPED (no second user)");
}

server.close();
await sleep(100);
fs.rmSync(runDir, { recursive: true, force: true });
if (failures.length) {
  console.log(`\nFAILED: ${failures.join(", ")}`);
  process.exit(1);
}
console.log("\nTCP OK");
process.exit(0);
