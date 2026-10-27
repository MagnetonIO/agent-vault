# agent-vault

TypeScript / Node 24 pnpm monorepo (ESM, `tsc -b` project references, Vitest, Biome). Local-first secrets vault so AI agent harnesses can use credentials without seeing them.

## Current state

- Git repo; MVP work on `feat/mvp` (remote `origin`: MagnetonIO/agent-vault, private).
- Design plan: `docs/design.md`.
- `.mimocode/` is local runtime state (gitignored) — not source.
- Packages in `packages/*`, all `@agent-vault/<pkg>`: crypto, detect, platform, core, daemon, cli, mcp, adapters.
- Commands (run from repo root):

| Command | What it does |
|---|---|
| `pnpm i` | Install deps |
| `pnpm build` | `tsc -b` all packages |
| `pnpm typecheck` | `tsc` over tests and `vitest.config.ts` (no emit) |
| `pnpm test` | `vitest run` |
| `pnpm lint` | `biome check .` |
| `pnpm dev` | `tsx watch` the CLI daemon |

## Conventions

- **Sandbox rule:** dev and test runs never touch the real keychain or harness configs. Tests set `HOME`/`USERPROFILE`/`CODEX_HOME`/`AGENT_VAULT_HOME` to a temp dir and inject a `MemoryKeyStore`, or use the keyfile store via `AGENT_VAULT_KEYFILE_PASSPHRASE`. That variable is the headless/CI unlock for the keyfile store only; interactive use reads the passphrase from a TTY. Secrets themselves never come from argv or env.
- Tests live in `packages/<pkg>/test/`; cross-package tests in `test/e2e/`.
- Commit after every task (conventional commits).
- pnpm 12 blocks unreviewed install scripts; each native dep needs an explicit `allowBuilds` entry in `pnpm-workspace.yaml`.
- CI must be green on macOS, Linux, and Windows.
