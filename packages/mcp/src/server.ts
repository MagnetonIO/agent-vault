import { readFileSync } from "node:fs";
import { ensureDaemon, type IpcClient, openUrl } from "@agent-vault/daemon";
import { getPaths } from "@agent-vault/platform";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { DEFAULT_LIMITS, type Harness, type Limits, registerTools } from "./tools.js";

export type McpServerOptions = {
  /** A fresh daemon connection per call, started on demand. Default: `ensureDaemon(getPaths())`. */
  connectDaemon?: (() => Promise<IpcClient>) | undefined;
  /** Open the capture link for clients that cannot show it. Default: the system browser. */
  openUrl?: ((url: string) => Promise<void>) | undefined;
  limits?: Partial<Limits> | undefined;
};

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
  version: string;
};

/** The audit attribution for an MCP client, from the name it announced at `initialize`. */
export function harnessFor(clientName: string | undefined): Harness {
  const name = (clientName ?? "").toLowerCase();
  if (name.includes("claude")) return "claude-code";
  if (name.includes("codex")) return "codex";
  if (name.includes("opencode")) return "opencode";
  return "mcp";
}

/** An MCP server with the vault tools. Nothing connects to the daemon until a tool is called. */
export function createMcpServer(opts: McpServerOptions = {}): McpServer {
  const server = new McpServer({ name: "agent-vault", version: pkg.version });
  registerTools(server, {
    connect: opts.connectDaemon ?? (() => ensureDaemon(getPaths())),
    openUrl: opts.openUrl ?? openUrl,
    limits: { ...DEFAULT_LIMITS, ...opts.limits },
    harness: () => harnessFor(server.server.getClientVersion()?.name),
  });
  return server;
}

/**
 * Serve MCP on stdin/stdout until the client hangs up. stdout carries protocol frames only; the
 * transport owns it, so nothing here (or in a tool) may write to it.
 */
export async function runStdio(opts: McpServerOptions = {}): Promise<void> {
  const server = createMcpServer(opts);
  const closed = new Promise<void>((resolve) => {
    server.server.onclose = resolve;
  });
  // The SDK's stdio transport does not notice the client closing stdin.
  process.stdin.once("end", () => void server.close());
  await server.connect(new StdioServerTransport());
  await closed;
}
