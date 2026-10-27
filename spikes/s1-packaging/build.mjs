// Builds dist/: bundle (main.cjs), addons/*.node, and the SEA binary (s1-spike[.exe]).
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { inject } from "postject";

const root = path.dirname(fileURLToPath(import.meta.url));
const dist = path.join(root, "dist");
const addons = path.join(dist, "addons");
const exe = path.join(dist, process.platform === "win32" ? "s1-spike.exe" : "s1-spike");
const require = createRequire(import.meta.url);

rmSync(dist, { recursive: true, force: true });
mkdirSync(addons, { recursive: true });

// 1. Bundle the JS. CJS because the SEA main script is a CJS script. Native code stays out.
await build({
  entryPoints: [path.join(root, "src/main.cjs")],
  outfile: path.join(dist, "main.cjs"),
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node24",
  logLevel: "warning",
});

// 2. Collect the .node files beside the bundle/binary under fixed names.
const isMusl =
  process.platform === "linux" && !process.report.getReport().header.glibcVersionRuntime;
const sqliteDir = path.dirname(require.resolve("better-sqlite3/package.json"));
const sqliteTarget = `${isMusl ? "linuxmusl" : process.platform}-${process.arch}`;
copyFileSync(
  path.join(sqliteDir, "prebuilds", `${sqliteTarget}.node`),
  path.join(addons, "better_sqlite3.node"),
);

// pnpm installs only the optional dep matching this platform: @napi-rs/keyring-<triple>.
const store = path.join(root, "node_modules/.pnpm");
const keyringPkg = readdirSync(store).find((d) => d.startsWith("@napi-rs+keyring-"));
if (!keyringPkg) throw new Error("no @napi-rs/keyring-<platform> package installed");
const keyringName = keyringPkg.slice(0, keyringPkg.lastIndexOf("@")).replace("+", "/");
const keyringPkgDir = path.join(store, keyringPkg, "node_modules", keyringName);
const keyringNode = readdirSync(keyringPkgDir).find((f) => f.endsWith(".node"));
copyFileSync(path.join(keyringPkgDir, keyringNode), path.join(addons, "keyring.node"));

// 3. SEA blob.
const seaConfig = path.join(dist, "sea-config.json");
const blob = path.join(dist, "sea-prep.blob");
writeFileSync(
  seaConfig,
  JSON.stringify({
    main: path.join(dist, "main.cjs"),
    output: blob,
    disableExperimentalSEAWarning: true,
  }),
);
execFileSync(process.execPath, ["--experimental-sea-config", seaConfig], { stdio: "inherit" });

// 4. Copy node, strip signature (macOS), inject, re-sign ad hoc (macOS).
copyFileSync(process.execPath, exe);
if (process.platform === "darwin") execFileSync("codesign", ["--remove-signature", exe]);
await inject(exe, "NODE_SEA_BLOB", readFileSync(blob), {
  sentinelFuse: "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
  ...(process.platform === "darwin" ? { machoSegmentName: "NODE_SEA" } : {}),
});
if (process.platform === "darwin") execFileSync("codesign", ["--sign", "-", exe]);

console.log(`built ${exe}`);
console.log(`addons: ${readdirSync(addons).join(", ")}`);
