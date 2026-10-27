// Windows only. Q1 (pipe DACL of a plain Node net server) and Q2 (pipe squatting, both orders).
import net from "node:net";
import path from "node:path";
import {
  ev,
  exchange,
  hasOtherUser,
  indent,
  PUBLIC,
  pipeName,
  preparePublic,
  readOr,
  runAsOther,
  runScript,
  section,
  sleep,
  tryListen,
  waitForLine,
} from "./lib.mjs";

if (process.platform !== "win32") throw new Error("win-pipe.mjs is Windows only");

// ---- SDDL decoding ---------------------------------------------------------------------------
const ALIASES = {
  WD: "Everyone",
  AN: "ANONYMOUS LOGON",
  BU: "BUILTIN\\Users",
  AU: "Authenticated Users",
  IU: "INTERACTIVE",
  NU: "NETWORK",
  SY: "SYSTEM",
  BA: "BUILTIN\\Administrators",
  CO: "CREATOR OWNER",
  OW: "OWNER RIGHTS",
  LS: "LOCAL SERVICE",
  NS: "NETWORK SERVICE",
  AC: "ALL APPLICATION PACKAGES",
};
const BROAD = new Set(["WD", "AN", "BU", "AU", "IU", "NU", "AC", "S-1-1-0", "S-1-5-7", "S-1-5-11"]);
const RIGHTS = {
  FA: 0x1f01ff,
  FR: 0x120089,
  FW: 0x120116,
  FX: 0x1200a0,
  GA: 0x10000000,
  GR: 0x80000000,
  GW: 0x40000000,
  GX: 0x20000000,
};

function maskOf(s) {
  if (/^0x/i.test(s)) return Number.parseInt(s, 16) >>> 0;
  let m = 0;
  for (let i = 0; i + 1 < s.length; i += 2) m |= RIGHTS[s.slice(i, i + 2)] ?? 0;
  return m >>> 0;
}

/** FILE_READ_DATA=1, FILE_WRITE_DATA=2, FILE_CREATE_PIPE_INSTANCE (append)=4 for pipes. */
function describeAce(ace) {
  const f = ace.split(";");
  const [type, , rights, , , sid] = f;
  const m = maskOf(rights);
  const gen = (b) => (m & b) !== 0;
  const read = gen(0x1) || gen(0x80000000) || gen(0x10000000);
  const write = gen(0x2) || gen(0x40000000) || gen(0x10000000);
  const createInstance = gen(0x4) || gen(0x10000000);
  return {
    type,
    sid,
    rights,
    name: ALIASES[sid] ?? sid,
    read,
    write,
    createInstance,
    broad: BROAD.has(sid),
  };
}

function analyse(label, sddl) {
  const dacl = /D:(.*?)(?:S:|$)/s.exec(sddl)?.[1] ?? "";
  const aces = [...dacl.matchAll(/\(([^)]*)\)/g)].map((m) => describeAce(m[1]));
  console.log(`  ${label} owner/group part: ${sddl.split("D:")[0]}`);
  for (const a of aces) {
    console.log(
      `  ${label} ACE type=${a.type} trustee=${a.name} (${a.sid}) rights=${a.rights} read=${a.read} write=${a.write} createInstance=${a.createInstance}`,
    );
  }
  const broadAllow = aces.filter((a) => a.type === "A" && a.broad);
  const summary =
    broadAllow
      .map((a) => `${a.name}: read=${a.read} write=${a.write} createInstance=${a.createInstance}`)
      .join("; ") || "no allow ACE for Everyone/Anonymous/Users/Authenticated Users/Network";
  ev(`pipe-acl-broad-${label}`, summary);
  return aces;
}

const attach = (server) =>
  server.on("connection", (s) => {
    s.on("error", () => {});
    s.once("data", () => s.end("VAULTD\n"));
  });

async function ping(name) {
  const r = await exchange({ path: name }, ["ping\n"], 4000);
  return r.data.trim() || `(no reply, error=${r.error}, closed=${r.serverClosed})`;
}

// ---- main ------------------------------------------------------------------------------------
await preparePublic();
const OUT = (n) => path.join(PUBLIC, n);
const other = hasOtherUser();
console.log(`node ${process.version}; second user available: ${other}`);

// Q1: plain Node pipe server, DACL dump
section("Q1: pipe DACL of net.createServer().listen(pipe)");
const NAME = pipeName();
const vaultd = net.createServer();
attach(vaultd);
const l1 = await tryListen(vaultd, NAME);
ev("pipe-listen", l1.ok ? `listen(${NAME}) ok` : `listen failed ${l1.code} ${l1.message}`);
if (!l1.ok) process.exit(1);

const dump = await runScript("acl-dump.ps1", ["-Pipe", NAME]);
console.log(indent(dump.stdout + dump.stderr));
for (const [label, re] of [
  ["A-GetAcl", /^A\.sddl: (.*)$/m],
  ["B-GetNamedSecurityInfo", /^B\.sddl: (.*)$/m],
  ["C-PipeSecurity", /^C\.sddl: (.*)$/m],
]) {
  const sddl = re.exec(dump.stdout)?.[1]?.trim();
  if (sddl) {
    ev(`pipe-sddl-${label}`, sddl);
    analyse(label, sddl);
  } else {
    ev(`pipe-sddl-${label}`, "unavailable (see FAILED line above)");
  }
}

section("Q1b: who can connect (same user, remote path, second user)");
ev("pipe-same-user-ping", await ping(NAME));
const same = await runScript("probe.ps1", ["-Pipe", NAME, "-Server", "localhost"]);
console.log(indent(same.stdout + same.stderr));
ev(
  "pipe-remote-path",
  (/PROBE pipe-connect-InOut: (.*)/.exec(same.stdout)?.[1] ?? "no result").slice(0, 200),
);
if (other) {
  const f = OUT("probe-pipe.txt");
  await runAsOther("probe.ps1", ["-Pipe", NAME], f);
  const t = await waitForLine(f, /pipe-connect-Out/, 20000);
  console.log(indent(t + readOr(`${f}.err`)));
  ev(
    "pipe-other-user",
    t
      .split(/\r?\n/)
      .filter((l) => l.startsWith("PROBE pipe"))
      .join(" | "),
  );
} else {
  ev("pipe-other-user", "SKIPPED (no second user)");
}

// Q2 order A: vaultd listens first, then a squatter tries the same name
section("Q2 order A: vaultd first, squatter second");
const dup = net.createServer();
const a1 = await tryListen(dup, NAME);
ev("squat-A-node-second-listen", a1.ok ? "SUCCEEDED (shared!)" : `${a1.code}: ${a1.message}`);
if (a1.ok) dup.close();
{
  const r = await runScript("squat.ps1", ["-Pipe", NAME, "-HoldSeconds", "2"]);
  const line = r.stdout.split(/\r?\n/).find((l) => l.startsWith("SQUAT")) ?? r.stdout + r.stderr;
  ev("squat-A-same-user-ps", line.trim());
}
if (other) {
  const f = OUT("squat-a-other.txt");
  await runAsOther("squat.ps1", ["-Pipe", NAME, "-Everyone", "-HoldSeconds", "2"], f);
  const t = await waitForLine(f, /SQUAT (created|create FAILED)/, 20000);
  ev("squat-A-other-user-ps", t.split(/\r?\n/).find((l) => l.startsWith("SQUAT")) ?? "no output");
} else {
  ev("squat-A-other-user-ps", "SKIPPED (no second user)");
}
vaultd.close();
await sleep(500);

// Q2 order B: squatter listens first, then vaultd tries
section("Q2 order B: squatter first, vaultd second");
const NAME_B1 = pipeName("-squat-b1");
const NAME_B2 = pipeName("-squat-b2");
{
  // squatter is the same user (no Everyone ACL)
  const sq = runScript("squat.ps1", ["-Pipe", NAME_B1, "-HoldSeconds", "12"]);
  await sleep(3000);
  const v = net.createServer();
  attach(v);
  const r = await tryListen(v, NAME_B1);
  ev(
    "squat-B-same-user-then-node-listen",
    r.ok ? "SUCCEEDED (shared!)" : `${r.code}: ${r.message}`,
  );
  if (r.ok) ev("squat-B-same-user-who-answers", await ping(NAME_B1));
  v.close();
  const res = await sq;
  console.log(indent(res.stdout + res.stderr));
}
if (other) {
  const f = OUT("squat-b2.txt");
  await runAsOther("squat.ps1", ["-Pipe", NAME_B2, "-Everyone", "-HoldSeconds", "15"], f, {
    wait: false,
  });
  const created = await waitForLine(f, /SQUAT (created|create FAILED)/, 20000);
  ev(
    "squat-B-other-user-created",
    created.split(/\r?\n/).find((l) => l.startsWith("SQUAT")) ?? "no output",
  );
  const v = net.createServer();
  attach(v);
  const r = await tryListen(v, NAME_B2);
  ev(
    "squat-B-other-user-then-node-listen",
    r.ok ? "SUCCEEDED (shared!)" : `${r.code}: ${r.message}`,
  );
  if (r.ok) ev("squat-B-other-user-who-answers", await ping(NAME_B2));
  v.close();
  await sleep(1500);
  console.log(indent(readOr(f)));
} else {
  ev("squat-B-other-user", "SKIPPED (no second user)");
}
process.exit(0);
