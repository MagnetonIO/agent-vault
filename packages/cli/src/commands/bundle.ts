import path from "node:path";
import type { BundleInfo } from "@agent-vault/core";
import type { Command } from "commander";
import { withDaemon } from "../context.js";
import { say } from "../output.js";

export function bundleCommand(program: Command): void {
  const bundle = program.command("bundle").description("named sets of secrets for `run --bundle`");

  bundle
    .command("create")
    .argument("<bundle>")
    .description("make an empty bundle")
    .action(async (name: string) => {
      await withDaemon((client) => client.call("bundle.create", { name }));
      say(`created bundle ${name}`);
    });

  bundle
    .command("grant")
    .argument("<bundle>")
    .argument("<ENV>", "environment variable the child sees")
    .argument("<secret>", "secret name")
    .description("put a secret in a bundle under an env var name")
    .action(async (name: string, env: string, secret: string) => {
      await withDaemon((client) => client.call("bundle.grant", { bundle: name, env, secret }));
      say(`granted ${secret} to ${name} as ${env}`);
    });

  bundle
    .command("allow-exe")
    .argument("<bundle>")
    .argument("<path>", "executable the bundle may be used with")
    .description("limit a bundle to an executable (repeat to allow several)")
    .action(async (name: string, exe: string) => {
      const abs = path.resolve(exe);
      await withDaemon((client) => client.call("bundle.allowExe", { bundle: name, path: abs }));
      say(`${name} may run ${abs}`);
    });

  bundle
    .command("list")
    .description("show bundles")
    .option("--json", "print BundleInfo[] as JSON")
    .action(async (opts: { json?: boolean }) => {
      const bundles = await withDaemon((client) => client.call<BundleInfo[]>("bundle.list"));
      if (opts.json) {
        say(JSON.stringify(bundles, null, 2));
        return;
      }
      if (bundles.length === 0) say("no bundles");
      for (const b of bundles) {
        say(b.name);
        for (const [envName, secret] of Object.entries(b.env)) say(`  ${envName} <- ${secret}`);
        for (const exe of b.exes) say(`  exe ${exe}`);
      }
    });
}
