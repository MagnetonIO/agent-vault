#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { runCli } from "./program.js";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
  version: string;
};

await runCli(process.argv, pkg.version);
