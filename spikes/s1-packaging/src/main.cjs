// Spike S1: SQLite (node:sqlite + better-sqlite3) and OS keyring from a plain-node run
// and from a Node SEA binary. Native addons are loaded with process.dlopen from an
// `addons/` directory that sits beside the binary (SEA) or beside this bundle (plain node).
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const sea = require("node:sea");

const SERVICE = "agent-vault-spike-s1";
const ACCOUNT = "test";

const baseDir = sea.isSea() ? path.dirname(process.execPath) : __dirname;
const warnings = [];
process.on("warning", (w) => warnings.push(`${w.name}: ${w.message}`));

function loadAddon(name) {
  const mod = { exports: {} };
  process.dlopen(mod, path.join(baseDir, "addons", name));
  return mod.exports;
}

function checkNodeSqlite(dir) {
  const { DatabaseSync } = require("node:sqlite");
  const db = new DatabaseSync(path.join(dir, "node-sqlite.db"));
  db.exec("CREATE TABLE t (k TEXT PRIMARY KEY, v BLOB)");
  db.prepare("INSERT INTO t VALUES (?, ?)").run("a", Buffer.from("hello"));
  const row = db.prepare("SELECT v FROM t WHERE k = ?").get("a");
  db.close();
  if (Buffer.from(row.v).toString() !== "hello") throw new Error("node:sqlite roundtrip mismatch");
}

function checkBetterSqlite(dir) {
  const Database = require("better-sqlite3");
  const db = new Database(path.join(dir, "better-sqlite3.db"), {
    nativeBinding: loadAddon("better_sqlite3.node"),
  });
  db.exec("CREATE TABLE t (k TEXT PRIMARY KEY, v BLOB)");
  db.prepare("INSERT INTO t VALUES (?, ?)").run("a", Buffer.from("hello"));
  const row = db.prepare("SELECT v FROM t WHERE k = ?").get("a");
  db.close();
  if (Buffer.from(row.v).toString() !== "hello") {
    throw new Error("better-sqlite3 roundtrip mismatch");
  }
}

function checkKeyring() {
  const { Entry } = loadAddon("keyring.node");
  // Pin Linux to Secret Service: the default silently falls back to the kernel keyutils
  // keyring, which does not survive a reboot. The option is ignored on macOS/Windows.
  // SPIKE_NO_PIN=1 is a control: it drops the pin to show the pin is what prevents the fallback.
  const options =
    process.env.SPIKE_NO_PIN === "1" ? undefined : { linux: { store: "secret-service" } };
  const entry = new Entry(SERVICE, ACCOUNT, options);
  const secret = `spike-${process.pid}-${Date.now()}`;
  try {
    entry.setPassword(secret);
    const got = entry.getPassword();
    if (got !== secret) throw new Error(`keyring roundtrip mismatch: ${got}`);
  } finally {
    try {
      entry.deletePassword();
    } catch (err) {
      console.error(`keyring cleanup failed: ${err.message}`);
    }
  }
  const after = entry.getPassword();
  if (after != null) throw new Error("keyring entry still present after delete");
}

function run(label, fn) {
  try {
    fn();
    console.log(`${label}: ok`);
  } catch (err) {
    console.log(`${label}: FAIL ${err.stack ?? err}`);
    process.exitCode = 1;
  }
}

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "s1-spike-"));
console.log(`node ${process.version} ${process.platform}-${process.arch} sea=${sea.isSea()}`);
run("node:sqlite", () => checkNodeSqlite(dir));
run("better-sqlite3", () => checkBetterSqlite(dir));
if (process.env.SPIKE_SKIP_KEYRING === "1") {
  // Addon load only; no Entry is constructed, so no credential store is touched.
  run("keyring addon load", () => {
    if (typeof loadAddon("keyring.node").Entry !== "function") throw new Error("no Entry export");
  });
  console.log("keyring: SKIPPED (SPIKE_SKIP_KEYRING=1)");
} else {
  run("keyring", checkKeyring);
}
fs.rmSync(dir, { recursive: true, force: true });

setImmediate(() => {
  console.log(`warnings: ${warnings.length ? warnings.join(" | ") : "none"}`);
  if (!process.exitCode) console.log("OK");
});
