// macOS + Linux. Q4: unix socket inside a 0700 dir; socket mode vs umask; peer credentials.
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { ev, run, section, sleep, tryListen } from "./lib.mjs";
import { dirsFor, ensurePrivateDir, resolveSocket, SOCKET_MAX_BYTES } from "./paths.mjs";

if (process.platform === "win32") throw new Error("posix.mjs is POSIX only");

const octal = (m) => (m & 0o7777).toString(8).padStart(4, "0");
const base = `/tmp/av-s2-${process.pid}`; // /tmp on purpose: traversable by other users, so the dir mode is the only gate
const failures = [];
console.log(
  `node ${process.version}; ${os.type()} ${os.arch()}; uid=${process.getuid()}; default umask=${octal(process.umask())}`,
);

fs.mkdirSync(base, { mode: 0o700 });
ev(
  "dir-mode",
  `mkdir(mode 0700) -> ${octal(fs.statSync(base).mode)} owner uid=${fs.statSync(base).uid}`,
);

// ---- socket mode after listen(), per umask ---------------------------------------------------
section("socket mode after listen() per umask");
const startUmask = process.umask();
for (const um of [0o022, 0o077, 0o000]) {
  process.umask(um);
  const sock = path.join(base, `m${um.toString(8)}.sock`);
  const s = net.createServer();
  const r = await tryListen(s, sock);
  const mode = fs.statSync(sock).mode;
  ev(
    `sock-mode-umask-${um.toString(8).padStart(3, "0")}`,
    `${r.ok ? "listen ok" : r.code}; socket mode=${octal(mode)}`,
  );
  s.close();
}
process.umask(startUmask);

{
  const sock = path.join(base, "chmod.sock");
  const s = net.createServer();
  await tryListen(s, sock);
  const before = octal(fs.statSync(sock).mode);
  fs.chmodSync(sock, 0o600);
  ev("sock-chmod-0600", `before=${before} after=${octal(fs.statSync(sock).mode)}`);
  const c = await run(process.execPath, [
    "-e",
    `const s=require('net').connect(${JSON.stringify(sock)});s.on('connect',()=>{console.log('CONNECTED');s.end()});s.on('error',e=>console.log('ERR '+e.code))`,
  ]);
  ev("sock-after-chmod-owner-connect", c.stdout.trim());
  s.close();
}
{
  const sock = path.join(base, "opts.sock");
  const s = net.createServer();
  await tryListen(s, { path: sock, readableAll: true, writableAll: true });
  ev(
    "sock-listen-readableAll-writableAll",
    `socket mode=${octal(fs.statSync(sock).mode)} (opt-in widening exists; never use)`,
  );
  s.close();
}

// ---- other local user: does the 0700 dir alone keep them out? --------------------------------
section("another local user (sudo -u nobody)");
const NODE_CONNECT = (sock) =>
  `const s=require('net').connect(${JSON.stringify(sock)});s.on('connect',()=>{console.log('CONNECTED');s.end()});s.on('error',e=>console.log('ERR '+e.code))`;
/** Connect as `nobody`. macOS runner's node lives in a user-only dir, so fall back to nc -U. */
async function asNobody(sock) {
  const viaNode = await run(
    "sudo",
    ["-n", "-u", "nobody", process.execPath, "-e", NODE_CONNECT(sock)],
    { cwd: "/" },
  );
  if (viaNode.stdout.trim()) return viaNode.stdout.trim();
  const viaNc = await run("sudo", ["-n", "-u", "nobody", "/usr/bin/nc", "-U", "-w", "1", sock], {
    cwd: "/",
  });
  const err = viaNc.stderr.trim().slice(0, 160);
  return viaNc.code === 0
    ? "CONNECTED (via nc -U)"
    : `FAILED (via nc -U): ${err || `exit ${viaNc.code}`}`;
}
{
  const sock = path.join(base, "wide.sock");
  process.umask(0o000);
  const s = net.createServer((c) => c.on("error", () => {}).end());
  await tryListen(s, sock);
  process.umask(startUmask);
  ev(
    "wide-sock-mode",
    `socket mode=${octal(fs.statSync(sock).mode)} dir mode=${octal(fs.statSync(base).mode)}`,
  );
  const closed = await asNobody(sock);
  ev("nobody-vs-0700-dir", `${closed} (socket itself is 0777)`);
  fs.chmodSync(base, 0o755);
  const open = await asNobody(sock);
  ev(
    "nobody-vs-0755-dir-control",
    `${open} (control: must be CONNECTED, else test is inconclusive)`,
  );
  fs.chmodSync(base, 0o700);
  s.close();
}

// ---- squat in a shared parent: pre-created dir owned by someone else --------------------------
section("pre-created directory owned by another user");
{
  const evil = `/tmp/av-s2-evil-${process.pid}`;
  const mk = await run("sudo", ["-n", "-u", "nobody", "mkdir", "-m", "0777", evil], { cwd: "/" });
  if (mk.code === 0) {
    const st = fs.lstatSync(evil);
    const safe = st.uid === process.getuid() && (st.mode & 0o077) === 0 && st.isDirectory();
    ev(
      "dir-ownership-check",
      `dir owner uid=${st.uid} mode=${octal(st.mode)} -> daemon check (uid==me && mode&077==0 && isDirectory) says safe=${safe}`,
    );
    if (safe) failures.push("dir-ownership-check");
    await run("sudo", ["-n", "rm", "-rf", evil]); // sticky /tmp: only the owner may remove it
  } else {
    ev(
      "dir-ownership-check",
      `SKIPPED (sudo -u nobody mkdir failed: ${mk.stderr.trim().slice(0, 120)})`,
    );
  }
}

// ---- duplicate listen / stale socket ----------------------------------------------------------
section("squat / stale socket on the same path");
{
  const sock = path.join(base, "dup.sock");
  const a = net.createServer();
  await tryListen(a, sock);
  const b = net.createServer();
  const r = await tryListen(b, sock);
  ev("posix-second-listen-live", r.ok ? "SUCCEEDED (shared!)" : `${r.code}`);
  a.close();

  const stale = path.join(base, "stale.sock");
  const child = spawn(process.execPath, [
    "-e",
    `require('net').createServer().listen(${JSON.stringify(stale)},()=>console.log('up'))`,
  ]);
  await new Promise((res) => child.stdout.once("data", res));
  child.kill("SIGKILL");
  await sleep(300);
  ev("posix-stale-file-left", `exists after SIGKILL: ${fs.existsSync(stale)}`);
  const c = net.createServer();
  const r2 = await tryListen(c, stale);
  ev("posix-listen-over-stale", r2.ok ? "ok" : `${r2.code}`);
  const probe = await new Promise((res) => {
    const x = net.connect(stale);
    x.on("connect", () => res("CONNECTED"));
    x.on("error", (e) => res(e.code));
  });
  ev("posix-connect-to-stale", probe);
  fs.rmSync(stale, { force: true });
  const d = net.createServer();
  const r3 = await tryListen(d, stale);
  ev("posix-listen-after-unlink", r3.ok ? "ok" : `${r3.code}`);
  d.close();
}

// ---- sun_path length --------------------------------------------------------------------------
section("socket path length limit");
{
  let maxOk = 0;
  for (let len = 90; len <= 120; len++) {
    const dir = base;
    const name = "p".repeat(Math.max(1, len - dir.length - 1));
    const p = path.join(dir, name);
    const s = net.createServer();
    const r = await tryListen(s, p);
    if (r.ok) {
      maxOk = p.length;
      s.close();
    } else {
      ev("path-length-first-failure", `len=${p.length} -> ${r.code}: ${r.message.slice(0, 120)}`);
      break;
    }
  }
  ev("path-length-max-ok", `${maxOk} chars`);
}

// ---- peer credentials: is there any public API? -----------------------------------------------
section("peer credentials in pure Node");
{
  const names = new Set();
  const collect = (o) => {
    for (let p = o; p && p !== Object.prototype; p = Object.getPrototypeOf(p)) {
      for (const k of Object.getOwnPropertyNames(p)) names.add(k);
    }
  };
  const sock = path.join(base, "cred.sock");
  const server = net.createServer();
  const seen = new Promise((res) => server.once("connection", res));
  await tryListen(server, sock);
  const client = net.connect(sock);
  const serverSide = await seen;
  collect(serverSide);
  if (serverSide._handle) collect(serverSide._handle);
  collect(server);
  collect(net);
  const hits = [...names].filter((k) => /cred|peer|\buid\b|\bgid\b|pid/i.test(k)).sort();
  ev(
    "peer-cred-api-scan",
    `${names.size} property names scanned on net, Server, Socket and its handle; matches for /cred|peer|uid|gid|pid/: ${hits.join(", ") || "none"}`,
  );
  ev(
    "peer-cred-getpeername",
    `serverSide._getpeername() = ${JSON.stringify(serverSide._getpeername())} (address info only, no uid)`,
  );
  client.destroy();
  server.close();
}

// ---- where the socket lives: runtimeDir rules + the byte-length fallback -------------------
section("socket dir resolution (paths.mjs)");
{
  const tag = `/tmp/avp-${process.pid}`;
  const cleanup = [];
  const check = async (id, opts) => {
    const r = resolveSocket(opts);
    ensurePrivateDir(r.dir);
    const s = net.createServer();
    const l = await tryListen(s, r.path);
    const st = fs.statSync(r.dir);
    ev(
      id,
      `path=${r.path} bytes=${Buffer.byteLength(r.path)} fallback=${r.fallback} listen=${l.ok ? "ok" : `${l.code}`} dirMode=${octal(st.mode)} dirUid==me:${st.uid === process.getuid()}`,
    );
    if (!l.ok || (st.mode & 0o077) !== 0) failures.push(id);
    s.close();
    return r;
  };
  const mk = (n) => {
    const d = `${tag}-${n}`;
    fs.mkdirSync(d, { recursive: true, mode: 0o700 });
    cleanup.push(d);
    return d;
  };

  const xdg = mk("xdg");
  await check("path-linux-xdg-set", {
    platform: "linux",
    home: mk("h1"),
    env: { XDG_RUNTIME_DIR: xdg },
  });
  await check("path-linux-xdg-unset", { platform: "linux", home: mk("h2"), env: {} });
  await check("path-darwin-style", { platform: "darwin", home: mk("h3"), env: {} });
  ev(
    "path-darwin-real-home-length",
    `${Buffer.byteLength(resolveSocket({ platform: "darwin", home: os.homedir(), env: {} }).path)} bytes for this runner's real HOME ${os.homedir()} (limit ${SOCKET_MAX_BYTES.darwin})`,
  );

  const longHome = path.join(mk("h4"), "x".repeat(100));
  const fb = await check("path-fallback-long-home-darwin", {
    platform: "darwin",
    home: longHome,
    env: {},
  });
  ev("path-fallback-differs-from-normal", `${fb.fallback}`);
  await check("path-fallback-long-home-linux", { platform: "linux", home: longHome, env: {} });

  // multibyte: character count under the limit, UTF-8 byte count over it
  const mbHome = path.join(mk("h5"), "é".repeat(30));
  const mbNormal = path.join(
    dirsFor({ env: {}, platform: "darwin", home: mbHome }).runtimeDir,
    "vaultd.sock",
  );
  ev(
    "path-multibyte-sizes",
    `chars=${mbNormal.length} bytes=${Buffer.byteLength(mbNormal)} (limit ${SOCKET_MAX_BYTES.darwin})`,
  );
  fs.mkdirSync(path.dirname(mbNormal), { recursive: true });
  const raw = net.createServer();
  const rawR = await tryListen(raw, mbNormal);
  ev("path-multibyte-raw-listen", rawR.ok ? "ok" : `${rawR.code}`);
  if (rawR.ok) raw.close();
  const mb = await check("path-fallback-multibyte-home", {
    platform: "darwin",
    home: mbHome,
    env: {},
  });
  if (!mb.fallback && Buffer.byteLength(mb.path) > SOCKET_MAX_BYTES.darwin)
    failures.push("multibyte");

  // the fallback dir name is predictable: a dir pre-created by another user must be refused
  const sharedTmp = "/tmp";
  const evil = path.join(sharedTmp, `av-${process.getuid()}`);
  const mkEvil = await run("sudo", ["-n", "-u", "nobody", "mkdir", "-m", "0777", evil], {
    cwd: "/",
  });
  if (mkEvil.code === 0) {
    const r = resolveSocket({ platform: "darwin", home: longHome, env: {}, tmpdir: sharedTmp });
    let refused = "NOT refused";
    try {
      ensurePrivateDir(r.dir);
    } catch (e) {
      refused = `refused: ${e.message}`;
    }
    ev("path-fallback-dir-precreated-by-other-user", refused);
    if (!refused.startsWith("refused")) failures.push("fallback-precreated");
    await run("sudo", ["-n", "rm", "-rf", evil]);
  } else {
    ev(
      "path-fallback-dir-precreated-by-other-user",
      `SKIPPED (${mkEvil.stderr.trim().slice(0, 100)})`,
    );
  }
  fs.rmSync(path.join(os.tmpdir(), `av-${process.getuid()}`), { recursive: true, force: true });
  for (const d of cleanup) fs.rmSync(d, { recursive: true, force: true });
}

fs.rmSync(base, { recursive: true, force: true });
if (failures.length) {
  console.log(`\nFAILED: ${failures.join(", ")}`);
  process.exit(1);
}
console.log("\nPOSIX OK");
