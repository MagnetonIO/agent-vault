import type { SecretMeta, Vault } from "@agent-vault/core";
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

/**
 * Store `value`. With no `name`, detect the secret type and suggest a name (or fall back to
 * `secret/unnamed-<date>`). The one storage path for `secret.put` and the capture page. The
 * caller owns `value` and zeroes it.
 */
export function storeSecret(
  vault: Vault,
  input: {
    name?: string | undefined;
    value: Buffer;
    type?: string | undefined;
    tags?: string[] | undefined;
  },
): SecretMeta {
  let { name, type } = input;
  if (name === undefined) {
    const hit = detectSecrets(input.value.toString("utf8"), { isTaken: (n) => vault.has(n) })[0];
    name = hit ? hit.suggestedName : unnamed(vault);
    type ??= hit ? hit.ruleId : "generic";
  }
  return vault.putSecret(name, input.value, {
    ...(type !== undefined && { type }),
    ...(input.tags !== undefined && { tags: input.tags }),
  });
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
        ctx.audit.secretName = given; // so a failed put is still logged under its name
        const meta = storeSecret(ctx.vault(), { name: given, value, type, tags });
        ctx.audit.secretName = meta.name;
        return meta;
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
