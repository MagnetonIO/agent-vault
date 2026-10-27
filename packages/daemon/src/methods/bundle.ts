import { allowExe, createBundle, grant, listBundles } from "@agent-vault/core";
import { paramsObject, reqName, reqString } from "./params.js";
import type { Registry } from "./types.js";

export const bundleMethods: Registry = {
  "bundle.create": {
    mutates: true,
    returnsSecret: false,
    handler: (ctx, params) => {
      const name = reqName(paramsObject(params, ["name", "harness"]), "name");
      ctx.audit.bundle = name;
      createBundle(ctx.vault(), name);
      return { ok: true };
    },
  },
  "bundle.grant": {
    mutates: true,
    returnsSecret: false,
    handler: (ctx, params) => {
      const p = paramsObject(params, ["bundle", "env", "secret", "harness"]);
      const bundle = reqName(p, "bundle");
      const env = reqString(p, "env");
      const secret = reqName(p, "secret");
      ctx.audit.bundle = bundle;
      ctx.audit.secretName = secret;
      grant(ctx.vault(), bundle, { env, secret });
      return { ok: true };
    },
  },
  "bundle.allowExe": {
    mutates: true,
    returnsSecret: false,
    handler: (ctx, params) => {
      const p = paramsObject(params, ["bundle", "path", "harness"]);
      const bundle = reqName(p, "bundle");
      const exe = reqString(p, "path");
      ctx.audit.bundle = bundle;
      allowExe(ctx.vault(), bundle, exe);
      return { ok: true };
    },
  },
  "bundle.list": {
    mutates: false,
    returnsSecret: false,
    handler: (ctx, params) => {
      paramsObject(params, []);
      return listBundles(ctx.vault());
    },
  },
};
