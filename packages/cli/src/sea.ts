// The entry of the single-file binary (scripts/build-sea.mjs). It has no package.json to read, so
// the build replaces `__SEA_VERSION__`.
import { runCli } from "./program.js";

declare const __SEA_VERSION__: string;

void runCli(process.argv, __SEA_VERSION__);
