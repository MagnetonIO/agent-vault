import { randomBytes } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { describe, expect, test } from "vitest";
import { connect } from "../src/client.js";
import { DaemonIdentityError } from "../src/errors.js";
import { handshakeMac, newNonce } from "../src/handshake.js";
import { type endpointFor, RawPeer, useDaemon, useTmp } from "./helpers.js";

const tcp = (env: { endpoint: ReturnType<typeof endpointFor> }) => {
  if (env.endpoint.kind !== "tcp") throw new Error("expected a tcp endpoint");
  return env.endpoint;
};

const readToken = (env: { endpoint: ReturnType<typeof endpointFor> }): Buffer =>
  Buffer.from(fs.readFileSync(tcp(env).tokenFile, "utf8").trim(), "hex");

const readPort = (env: { endpoint: ReturnType<typeof endpointFor> }): number =>
  (JSON.parse(fs.readFileSync(tcp(env).endpointFile, "utf8")) as { port: number }).port;

/** Collects every byte a client sends to a server of ours. */
class Listener {
  readonly received: Buffer[] = [];
  readonly sockets = new Set<net.Socket>();
  readonly server: net.Server;
  port = 0;

  constructor(onConnection: (socket: net.Socket, listener: Listener) => void) {
    this.server = net.createServer((socket) => {
      this.sockets.add(socket);
      socket.on("error", () => {});
      socket.on("data", (d: Buffer) => this.received.push(d));
      onConnection(socket, this);
    });
  }

  async listen(): Promise<this> {
    await new Promise<void>((r) => this.server.listen(0, "127.0.0.1", r));
    this.port = (this.server.address() as net.AddressInfo).port;
    return this;
  }

  get bytes(): string {
    return Buffer.concat(this.received).toString("latin1");
  }

  close(): void {
    this.server.close();
    for (const s of this.sockets) s.destroy();
  }
}

/** An endpoint pair in `dir` that points at `port` and holds `token`. */
function pointAt(dir: string, port: number, token: Buffer) {
  const endpoint = {
    kind: "tcp" as const,
    endpointFile: path.join(dir, "ep.json"),
    tokenFile: path.join(dir, "tok"),
  };
  fs.writeFileSync(endpoint.endpointFile, JSON.stringify({ port, pid: 1 }));
  fs.writeFileSync(endpoint.tokenFile, token.toString("hex"));
  return endpoint;
}

const NONCE_LINE = /^[0-9a-f]{64}\n$/;

describe("tcp handshake", () => {
  describe("against the real daemon", () => {
    const env = useDaemon("tcp", { init: true });
    const tmp = useTmp();

    test("the server MAC and the client MAC both bind both nonces", async () => {
      const token = readToken(env);
      const peer = await RawPeer.plain(readPort(env));
      try {
        const nonceC = newNonce();
        peer.send(`${nonceC}\n`);
        const reply = (await peer.line()) as string;
        const [mac, nonceS] = reply.split(" ") as [string, string];
        expect(mac).toBe(handshakeMac(token, "srv", nonceC, nonceS));

        peer.send(`${handshakeMac(token, "cli", nonceS, nonceC)}\n`);
        expect((await peer.rpc("status")).result).toMatchObject({ initialized: true });
      } finally {
        peer.destroy();
      }
    });

    test("a client MAC without the client nonce (the spike's format) is rejected", async () => {
      const token = readToken(env);
      const peer = await RawPeer.plain(readPort(env));
      const nonceC = newNonce();
      peer.send(`${nonceC}\n`);
      const nonceS = ((await peer.line()) as string).split(" ")[1] as string;
      const spikeMac = handshakeMac(token, "cli", nonceS, "");
      peer.send(`${spikeMac}\n{"jsonrpc":"2.0","id":1,"method":"status"}\n`);
      expect(await peer.line(1000)).toBeNull();
      expect(await peer.waitClosed()).toBe(true);
    });

    test("a client holding the wrong token is closed and served nothing", async () => {
      const wrong = randomBytes(32);
      const peer = await RawPeer.plain(readPort(env));
      const nonceC = newNonce();
      peer.send(`${nonceC}\n`);
      const reply = (await peer.line()) as string;
      const nonceS = reply.split(" ")[1] as string;
      peer.send(
        `${handshakeMac(wrong, "cli", nonceS, nonceC)}\n{"jsonrpc":"2.0","id":1,"method":"status"}\n`,
      );
      expect(await peer.line(1000)).toBeNull();
      expect(await peer.waitClosed()).toBe(true);
    });

    test("the server's MAC is not replayable as the client's", async () => {
      const peer = await RawPeer.plain(readPort(env));
      const nonceC = newNonce();
      peer.send(`${nonceC}\n`);
      const mac = ((await peer.line()) as string).split(" ")[0] as string;
      peer.send(`${mac}\n`);
      expect(await peer.line(1000)).toBeNull();
      expect(await peer.waitClosed()).toBe(true);
    });

    test.each([
      ["JSON-RPC as the first line", '{"jsonrpc":"2.0","id":1,"method":"status"}\n'],
      ["a 63-character nonce", `${"a".repeat(63)}\n`],
      ["an uppercase nonce", `${"A".repeat(64)}\n`],
    ])("%s: closed with nothing sent back", async (_, first) => {
      const peer = await RawPeer.plain(readPort(env));
      peer.send(first);
      expect(await peer.line(1000)).toBeNull();
      expect(await peer.waitClosed()).toBe(true);
    });

    test("an over-long handshake line is cut off at 200 bytes", async () => {
      const peer = await RawPeer.plain(readPort(env));
      peer.send("a".repeat(4096));
      expect(await peer.waitClosed(1000)).toBe(true);
    });

    test("a silent client is closed by the step timer", async () => {
      const peer = await RawPeer.plain(readPort(env));
      expect(await peer.waitClosed(3000)).toBe(true);
    });

    test("a client stalling after the server's reply is closed too", async () => {
      const peer = await RawPeer.plain(readPort(env));
      peer.send(`${newNonce()}\n`);
      expect(await peer.line()).not.toBeNull();
      expect(await peer.waitClosed(3000)).toBe(true);
    });

    test("the client sends only the nonce when the token is wrong", async () => {
      // A recording proxy in front of the real daemon, with a token file that does not match.
      const proxy = await new Listener((client) => {
        const upstream = net.connect(readPort(env), "127.0.0.1");
        upstream.on("error", () => client.destroy());
        upstream.on("data", (d) => client.write(d));
        client.on("data", (d: Buffer) => upstream.write(d));
        client.on("close", () => upstream.destroy());
      }).listen();
      try {
        const endpoint = pointAt(tmp.dir, proxy.port, randomBytes(32));
        await expect(connect(endpoint)).rejects.toBeInstanceOf(DaemonIdentityError);
        await new Promise((r) => setTimeout(r, 100));
        expect(proxy.bytes).toMatch(NONCE_LINE);
        expect(proxy.bytes).toHaveLength(65);
      } finally {
        proxy.close();
      }
    });
  });

  describe("against an impostor", () => {
    const tmp = useTmp();
    const token = randomBytes(32);

    const impostors: [string, (socket: net.Socket, nonceC: string) => void][] = [
      ["answers with a bogus MAC", (s) => s.write(`${"f".repeat(64)} ${newNonce()}\n`)],
      [
        "knows a different token",
        (s, nonceC) => {
          const nonceS = newNonce();
          s.write(`${handshakeMac(randomBytes(32), "srv", nonceC, nonceS)} ${nonceS}\n`);
        },
      ],
      [
        "MACs only the client nonce (no channel binding)",
        (s, nonceC) => {
          const nonceS = newNonce();
          s.write(`${handshakeMac(token, "srv", nonceC, "")} ${nonceS}\n`);
        },
      ],
      ["replies with something that is not a handshake line", (s) => s.write("ok\n")],
      ["replies with an endless line", (s) => s.write("a".repeat(4096))],
    ];

    test.each(impostors)(
      "%s: DaemonIdentityError, and only the nonce was sent",
      async (_, reply) => {
        const impostor = await new Listener((socket, listener) => {
          socket.on("data", () => {
            const first = listener.bytes.split("\n")[0] as string;
            if (listener.received.length === 1 && /^[0-9a-f]{64}$/.test(first))
              reply(socket, first);
          });
        }).listen();
        try {
          const endpoint = pointAt(tmp.dir, impostor.port, token);
          await expect(connect(endpoint)).rejects.toBeInstanceOf(DaemonIdentityError);
          await new Promise((r) => setTimeout(r, 100));
          expect(impostor.bytes).toMatch(NONCE_LINE);
        } finally {
          impostor.close();
        }
      },
    );

    test("a silent impostor times out as DaemonIdentityError with only the nonce sent", async () => {
      const impostor = await new Listener(() => {}).listen();
      try {
        const endpoint = pointAt(tmp.dir, impostor.port, token);
        await expect(connect(endpoint, { timeoutMs: 300 })).rejects.toBeInstanceOf(
          DaemonIdentityError,
        );
        expect(impostor.bytes).toMatch(NONCE_LINE);
      } finally {
        impostor.close();
      }
    });

    test("a daemon that hangs up during the handshake is an ordinary error, not an identity failure", async () => {
      const closer = await new Listener((socket) => socket.destroy()).listen();
      try {
        const endpoint = pointAt(tmp.dir, closer.port, token);
        const err = await connect(endpoint).then(
          () => null,
          (e: unknown) => e,
        );
        expect(err).toBeInstanceOf(Error);
        expect(err).not.toBeInstanceOf(DaemonIdentityError);
      } finally {
        closer.close();
      }
    });

    test("a missing or malformed token file is an error before any connection", async () => {
      const endpoint = pointAt(tmp.dir, 9, token);
      fs.writeFileSync(endpoint.tokenFile, "not-a-token");
      await expect(connect(endpoint)).rejects.toThrow(/could not read/);
      fs.rmSync(endpoint.tokenFile);
      await expect(connect(endpoint)).rejects.toThrow(/could not read/);
    });
  });
});
