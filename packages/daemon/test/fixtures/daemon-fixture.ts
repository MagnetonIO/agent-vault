// Stand-in for `agent-vault daemon run` (Task 14), spawned by the autostart test. The sandbox comes
// from the environment: AGENT_VAULT_HOME and the headless keyfile passphrase. It exits on its own
// when the sandbox dir is deleted, or after 30 s, so a failed test cannot leave it running.
import fs from "node:fs";
import path from "node:path";
import { getPaths, openKeyfileStore } from "@agent-vault/platform";
import { startDaemon } from "../../src/index.js";

const passphrase = process.env.AGENT_VAULT_KEYFILE_PASSPHRASE;
if (!process.env.AGENT_VAULT_HOME || !passphrase) {
  console.error("AGENT_VAULT_HOME and AGENT_VAULT_KEYFILE_PASSPHRASE are required");
  process.exit(2);
}

const paths = getPaths();
const daemon = await startDaemon({
  paths,
  store: openKeyfileStore(path.join(paths.dataDir, "root.key"), passphrase),
}).catch((err: unknown) => {
  // Losing the race to another instance (DaemonAlreadyRunningError) is the expected way to exit.
  process.exit(err instanceof Error && err.name === "DaemonAlreadyRunningError" ? 0 : 1);
});

let stopping = false;
const stop = async () => {
  if (stopping) return;
  stopping = true;
  await daemon.close().catch(() => {});
  process.exit(0);
};
setInterval(() => {
  if (!fs.existsSync(paths.dataDir)) void stop();
}, 200);
setTimeout(() => void stop(), 30_000);
