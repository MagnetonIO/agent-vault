#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { fastAllow } from "./hook-input.js";

// A hook runs before every prompt: answer the common case (no key) without loading the CLI.
if (await fastAllow(process.argv, process.stdin)) process.exit(0);

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
  version: string;
};
const { runCli } = await import("./program.js");

await runCli(process.argv, pkg.version);
