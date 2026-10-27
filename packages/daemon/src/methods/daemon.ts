import { appendAudit } from "@agent-vault/core";
import { deviceId } from "../device.js";
import { paramsObject } from "./params.js";
import type { Registry } from "./types.js";

export const daemonMethods: Registry = {
  "daemon.stop": {
    // Writes its own audit event, like `run.*`: the dispatcher's record would come too late.
    mutates: false,
    returnsSecret: false,
    handler: (ctx, params) => {
      paramsObject(params, []);
      // Logged before anything stops: if the log cannot be written, the daemon keeps running.
      if (ctx.state.vault) {
        appendAudit(ctx.state.vault, {
          deviceId,
          harness: "cli",
          actor: "rpc",
          operation: "daemon.stop",
          outcome: "brokered",
        });
      }
      // The daemon closes after this reply has been written.
      ctx.requestStop();
      return { stopping: true };
    },
  },
};
