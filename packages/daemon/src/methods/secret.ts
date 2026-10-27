import type { Vault } from "@agent-vault/core";
import { detectSecrets } from "@agent-vault/detect";
import { optName, optString, optTags, paramsObject, reqBase64, reqName } from "./params.js";
import type { Registry } from "./types.js";

const utcStamp = (d: Date): string =>
  `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, "0")}${String(d.getUTCDate()).padStart(2, "0")}`;

/** `secret/unnamed-<yyyymmdd>`, with `-2`, `-3`, … appended while the name is taken. */
function unnamed(vault: Vault, now = new Date()): string {
  const base = `secret/unnamed-${utcStamp(now)}`;
  let name = base;
  for (let n = 2; vault.has(name); n++) name = `${base}-${n}`;
  return name;
}

export const secretMethods: Registry = {
  "secret.list": {
    mutates: false,
    returnsSecret: false,
    handler: (ctx, params) => {
      paramsObject(params, []);
      return ctx.vault().list();
    },
  },
  "secret.put": {
    mutates: true,
    returnsSecret: false,
    handler: (ctx, params) => {
      const p = paramsObject(params, ["name", "valueB64", "type", "tags", "harness"]);
      const given = optName(p, "name");
      const type = optString(p, "type");
      const tags = optTags(p, "tags");
      const value = reqBase64(p, "valueB64");
      try {
        const vault = ctx.vault();
        let name = given;
        let kind = type;
        if (name === undefined) {
          const hit = detectSecrets(value.toString("utf8"), { isTaken: (n) => vault.has(n) })[0];
          name = hit ? hit.suggestedName : unnamed(vault);
          kind ??= hit ? hit.ruleId : "generic";
        }
        ctx.audit.secretName = name;
        return vault.putSecret(name, value, {
          ...(kind !== undefined && { type: kind }),
          ...(tags !== undefined && { tags }),
        });
      } finally {
        value.fill(0);
      }
    },
  },
  "secret.remove": {
    mutates: true,
    returnsSecret: false,
    handler: (ctx, params) => {
      const name = reqName(paramsObject(params, ["name", "harness"]), "name");
      ctx.audit.secretName = name;
      return { removed: ctx.vault().remove(name) };
    },
  },
};
