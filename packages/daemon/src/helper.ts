import { SecretNotFoundError } from "@agent-vault/core";
import { HelperNotAllowedError } from "./errors.js";
import { paramsObject, reqName } from "./methods/params.js";
import type { Registry } from "./methods/types.js";
import { decodeSecretText } from "./secret-text.js";

/** The tag that lets a secret out through `helper.get`. */
export const HELPER_TAG = "helper";

/**
 * The credential helper: hands a harness its own model key. The one method that returns secret
 * bytes, so it refuses every secret that was not tagged `helper` when it was stored. Audited as
 * `brokered`, or `blocked` when refused; the event names the secret, never the value.
 */
export const helperMethods: Registry = {
  "helper.get": {
    mutates: true,
    returnsSecret: true,
    handler: (ctx, params) => {
      const secret = reqName(paramsObject(params, ["secret", "harness"]), "secret");
      ctx.audit.secretName = secret;
      const vault = ctx.vault();
      const meta = vault.list().find((m) => m.name === secret);
      if (!meta) throw new SecretNotFoundError(secret);
      if (!meta.tags.includes(HELPER_TAG)) {
        ctx.audit.failure = "blocked";
        throw new HelperNotAllowedError(secret);
      }
      const bytes = vault.readValue(secret);
      try {
        return { value: decodeSecretText(secret, bytes) };
      } finally {
        bytes.fill(0);
      }
    },
  },
};
