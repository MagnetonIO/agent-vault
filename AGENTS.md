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
| `pnpm dist` | `pnpm build`, then the Node SEA binary for this platform in `dist-sea/<platform>-<arch>/` |

## Conventions

- **Sandbox rule:** dev and test runs never touch the real keychain or harness configs. Tests set `HOME`/`USERPROFILE`/`CODEX_HOME`/`AGENT_VAULT_HOME` to a temp dir and inject a `MemoryKeyStore`, or use the keyfile store via `AGENT_VAULT_KEYFILE_PASSPHRASE`. That variable is the headless/CI unlock for the keyfile store only; interactive use reads the passphrase from a TTY. Secrets themselves never come from argv or env.
- Tests live in `packages/<pkg>/test/`; cross-package tests in `test/e2e/`.
- Commit after every task (conventional commits).
- pnpm 12 blocks unreviewed install scripts; each native dep needs an explicit `allowBuilds` entry in `pnpm-workspace.yaml`.
- CI budget: Actions minutes are limited (macOS bills 10x, Windows 2x). Verify locally first. A push to `feat/**` runs Linux only; run the full 3-OS matrix once per milestone with `gh workflow run ci.yml -f full=true`. Batch commits and push rarely.
- Test fixtures build every key-shaped value at runtime (see `packages/detect/test/fixtures/fake-keys.ts`). Never put a string literal next to a `KEY`/`TOKEN`/`SECRET`/`PASSWORD` field. `.gitguardian.yaml` keeps scanners off `packages/*/test`, `test/e2e`, and `spikes`.

## Parallel work (worktrees)

Independent tasks run in parallel, one git worktree per task.

| Step | Command / rule |
|---|---|
| 1. Create | `git worktree add ../agent-vault-wt/<task> -b claude/<task> feat/mvp`, then `pnpm i --frozen-lockfile && pnpm build` inside it |
| 2. Work | One agent per worktree. Agents edit only their own worktree and commit to their own `claude/<task>` branch, **without pushing**. Branch names must start with `claude/` |
| 3. Verify | Locally: `pnpm build && pnpm typecheck && pnpm test && pnpm lint`. CI does not run on `claude/**` |
| 4. Merge | The controller merges into `feat/mvp` with `git merge --no-ff claude/<task>`. CLI commands register in `packages/cli/src/program.ts`; on lockfile conflicts run `pnpm i`. Then rerun `pnpm build && pnpm typecheck && pnpm test && pnpm lint` and push |
| 5. Clean up | Once merged: `git worktree remove ../agent-vault-wt/<task>`, `git branch -D claude/<task>`, and `git push origin --delete claude/<task>` if it was ever pushed |

Never push tags or publish to npm from a worktree. Stop each agent as soon as it reports; resume it only for a fix round.
