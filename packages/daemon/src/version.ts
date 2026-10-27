import fs from "node:fs";

/** This package's version. `../package.json` is the same file from `src/` and from `dist/`. */
export const VERSION: string = (
  JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
    version: string;
  }
).version;
