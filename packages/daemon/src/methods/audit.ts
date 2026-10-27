import { queryAudit, verifyAudit } from "@agent-vault/core";
import { invalid, optName, optString, paramsObject } from "./params.js";
import type { Registry } from "./types.js";

export const auditMethods: Registry = {
  "audit.query": {
    mutates: false,
    returnsSecret: false,
    handler: (ctx, params) => {
      const p = paramsObject(params, ["secretName", "since", "limit"]);
      const secretName = optName(p, "secretName");
      const since = optString(p, "since");
      if (since !== undefined && Number.isNaN(Date.parse(since))) {
        throw invalid("since", "must be an ISO timestamp");
      }
      const limit = p.limit;
      if (
        limit !== undefined &&
        !(typeof limit === "number" && Number.isInteger(limit) && limit > 0)
      ) {
        throw invalid("limit", "must be a positive integer");
      }
      return queryAudit(ctx.vault(), {
        ...(secretName !== undefined && { secretName }),
        ...(since !== undefined && { since }),
        ...(limit !== undefined && { limit: limit as number }),
      });
    },
  },
  "audit.verify": {
    mutates: false,
    returnsSecret: false,
    handler: (ctx, params) => {
      paramsObject(params, []);
      return verifyAudit(ctx.vault());
    },
  },
};
