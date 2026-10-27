// Builds the single-file CLI for THIS platform into dist-sea/<platform>-<arch>/ (Spike S1):
//   agent-vault[.exe]   node + the esbuild bundle of packages/cli, injected as a SEA blob
//   addons/keyring.node  the @napi-rs/keyring addon for this platform, loaded with process.dlopen
// Run `pnpm build` first (`pnpm dist` does). Cross-building is not supported: pnpm installs only
// the optional keyring package for the host, so each target is built on its own OS (release.yml).
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { inject } from "postject";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const target = `${process.platform}-${process.arch}`;
const outDir = path.join(root, "dist-sea", target);
const work = path.join(root, "dist-sea", ".build", target);
const exe = path.join(outDir, process.platform === "win32" ? "agent-vault.exe" : "agent-vault");
const entry = path.join(root, "packages/cli/dist/sea.js");

const readPkg = (dir) => JSON.parse(readFileSync(path.join(root, dir, "package.json"), "utf8"));
const cliVersion = readPkg("packages/cli").version;
const daemonVersion = readPkg("packages/daemon").version;

// The binary embeds whichever node runs this script. Releases pin an exact version (release.yml);
// a different one still builds, but it is not what ships.
const pinned = /^\s*NODE_VERSION:\s*(\S+)/m.exec(
  readFileSync(path.join(root, ".github/workflows/release.yml"), "utf8"),
)?.[1];
if (pinned && process.version !== `v${pinned}`) {
  console.warn(`warning: building with node ${process.version}, but releases pin v${pinned}`);
}

// A node that links libraries from a package manager (Homebrew) is not self-contained: the copy
// would need them on every user's machine. Best effort: any failure to look is ignored.
try {
  const linked =
    process.platform === "darwin"
      ? execFileSync("otool", ["-L", process.execPath], { encoding: "utf8" })
      : process.platform === "linux"
        ? execFileSync("ldd", [process.execPath], { encoding: "utf8" })
        : "";
  const external = linked
    .split("\n")
    .filter((l) => /\/(opt\/homebrew|usr\/local\/(opt|Cellar)|home\/linuxbrew)\/|libnode/.test(l));
  if (external.length > 0) {
    console.warn(
      `warning: ${process.execPath} is dynamically linked to libraries outside the system:\n${external.join("\n")}`,
    );
  }
} catch {
  // otool or ldd missing, or a static binary: nothing to report.
}

if (!existsSync(entry)) throw new Error(`${entry} is missing: run pnpm build first`);
rmSync(outDir, { recursive: true, force: true });
rmSync(work, { recursive: true, force: true });
mkdirSync(path.join(outDir, "addons"), { recursive: true });
mkdirSync(work, { recursive: true });

// The keyring addon: pnpm links exactly one `keyring-<triple>` package beside `@napi-rs/keyring`.
const fromPlatform = createRequire(path.join(root, "packages/platform/package.json"));
const scope = path.dirname(path.dirname(fromPlatform.resolve("@napi-rs/keyring/package.json")));
const triples = readdirSync(scope).filter((d) => d.startsWith("keyring-"));
if (triples.length !== 1) {
  throw new Error(`expected one @napi-rs/keyring-<platform> package in ${scope}, found ${triples}`);
}
const triple = path.join(realpathSync(path.join(scope, triples[0])));
const keyringNode = readdirSync(triple).find((f) => f.endsWith(".node"));
if (!keyringNode) throw new Error(`no .node file in ${triple}`);
copyFileSync(path.join(triple, keyringNode), path.join(outDir, "addons", "keyring.node"));

// A SEA `require` loads builtins only, so the addon is opened with process.dlopen from beside the
// binary, and the two things that read package.json or import.meta.url get a build-time value.
const KEYRING_SHIM = `
const fs = require("node:fs");
const path = require("node:path");
const file = path.join(path.dirname(fs.realpathSync(process.execPath)), "addons", "keyring.node");
const mod = { exports: {} };
try {
  process.dlopen(mod, file);
} catch (err) {
  throw new Error(\`cannot load \${file} (the addons directory must stay beside the binary): \${err.message}\`);
}
module.exports = mod.exports;
`;

/** @type {import("esbuild").Plugin} */
const seaPlugin = {
  name: "sea",
  setup(b) {
    b.onResolve({ filter: /^@napi-rs\/keyring$/ }, () => ({
      path: "keyring",
      namespace: "sea-shim",
    }));
    b.onLoad({ filter: /.*/, namespace: "sea-shim" }, () => ({
      contents: KEYRING_SHIM,
      loader: "js",
      resolveDir: root,
    }));
    b.onLoad({ filter: /packages[\\/]daemon[\\/]dist[\\/]version\.js$/ }, () => ({
      contents: `export const VERSION = ${JSON.stringify(daemonVersion)};`,
      loader: "js",
    }));
  },
};

const bundle = path.join(work, "main.cjs");
await build({
  entryPoints: [entry],
  outfile: bundle,
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node24",
  logLevel: "warning",
  plugins: [seaPlugin],
  define: { __SEA_VERSION__: JSON.stringify(cliVersion), "import.meta.url": "__importMetaUrl" },
  banner: {
    js: 'const __importMetaUrl = require("node:url").pathToFileURL(process.execPath).href;',
  },
});

const seaConfig = path.join(work, "sea-config.json");
const blob = path.join(work, "sea-prep.blob");
writeFileSync(
  seaConfig,
  JSON.stringify({ main: bundle, output: blob, disableExperimentalSEAWarning: true }),
);
execFileSync(process.execPath, ["--experimental-sea-config", seaConfig], { stdio: "inherit" });

// Copy node, drop its signature (macOS), inject, and sign ad hoc again (macOS).
copyFileSync(process.execPath, exe);
if (process.platform === "darwin") execFileSync("codesign", ["--remove-signature", exe]);
await inject(exe, "NODE_SEA_BLOB", readFileSync(blob), {
  sentinelFuse: "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
  ...(process.platform === "darwin" ? { machoSegmentName: "NODE_SEA" } : {}),
});
if (process.platform === "darwin") execFileSync("codesign", ["--sign", "-", exe]);

rmSync(work, { recursive: true, force: true });
console.log(`built ${exe} (node ${process.version}, cli ${cliVersion})`);
