import { asHarness } from "../device.js";
import { optInt, optName, paramsObject, reqString } from "./params.js";
import type { Registry } from "./types.js";

const WAIT_MAX_MS = 600_000;

/** Neither method touches secret bytes: the value goes browser to daemon, never through RPC. */
export const captureMethods: Registry = {
  "capture.begin": {
    mutates: false,
    returnsSecret: false,
    handler: (ctx, params) => {
      const p = paramsObject(params, ["name", "harness"]);
      return ctx.capture.begin({ name: optName(p, "name"), harness: asHarness(p.harness) });
    },
  },
  "capture.wait": {
    mutates: false,
    returnsSecret: false,
    handler: (ctx, params) => {
      const p = paramsObject(params, ["elicitationId", "timeoutMs"]);
      const timeoutMs = optInt(p, "timeoutMs", 1, WAIT_MAX_MS) ?? WAIT_MAX_MS;
      return ctx.capture.wait(reqString(p, "elicitationId"), timeoutMs);
    },
  },
};
