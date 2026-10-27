# Spike S3: harness hook behavior

Status: **done**. Code and evidence: `spikes/s3-hooks/` (throwaway). Measured 2026-10-26 on macOS with Claude Code 2.1.311, Codex CLI 0.164.0, OpenCode 2.1.4.

Everything ran against sandboxed config dirs (`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `XDG_*`) with the fake secret `AVCANARY_<uuid4>`. Model calls went to local mock endpoints, with **one exception**: one fake canary reached `api.openai.com` (HTTP 401) because Codex silently skips untrusted hooks (decision 2, disclosure at the end). Three items touched or may have touched real dirs; see "Commands run outside the sandbox". Methods and limits are at the end.

**Evidence convention.** `[E: file]` = raw log committed under `spikes/s3-hooks/evidence/`. `[not retained]` = observed once, log not retained. Files marked *summary* there (`canary-files.txt`, `scrub-resume.txt`, `env-probe.txt`) are hand-written notes, not raw logs.

## Decisions

| # | Decision | Why |
|---|----------|-----|
| 1 | **Path B works on all three**, but with different residue: Claude `-p` leaves 1 transcript line, Claude TUI leaves nothing, Codex exec leaves nothing, Codex TUI leaves `history.jsonl` (removable with `history.persistence = "none"`), OpenCode leaves the full message in `opencode.db`. | Measured, see "Files holding the canary" (evidence per row there). |
| 2 | **Codex: install must get the hook trusted, and `doctor` must prove it fires.** An untrusted hook is skipped silently and **the prompt goes to the model** (fail-open). | Measured: first untrusted run reached `api.openai.com` (401 unauthenticated) [not retained]; reproduced against a local mock: hook ran 0 times, canary reached the model endpoint, no warning [E: codex-untrusted-hook.txt]. |
| 3 | **Claude scrubbing cannot happen inside the `UserPromptSubmit` hook** and `Stop` does not fire after a block. Scrub on `SessionEnd` (works in `-p`, see "SessionEnd scrub"), plus a sweep at the next `SessionStart` as the fallback. | Transcript file does not exist yet at hook time in `-p` mode [E: claude-sessionend-scrub.txt]; `Stop` absent from blocked runs [not retained]. |
| 4 | **OpenCode ≥ 2.0 has no documented-name prompt hook, but `session.context` can redact or reject the outbound turn.** It cannot stop the local write. Use it for "never reaches the model", then scrub `opencode.db`. | Measured: model request bodies had no canary; DB still did. |
| 5 | **`apiKeyHelper` output is not exported to Bash tool subprocesses.** `ANTHROPIC_API_KEY` in the harness env is. | Real Bash tool call + positive control [E: claude-apikeyhelper-env.txt]. |
| 6 | **Scrub-then-resume works on all three** (harness stopped). Validate JSONL yourself: Codex resumes even with a corrupt line. | Claude [E: claude-sessionend-scrub.txt]; Codex and OpenCode [not retained] (`scrub-resume.txt` is a summary). |

## Claude Code

### Hook config

`$CLAUDE_CONFIG_DIR/settings.json` (default `~/.claude/settings.json`). `matcher` is ignored for `UserPromptSubmit`.

```json
{
  "hooks": {
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "node /path/claude-hook.mjs" }] }]
  }
}
```

### Real stdin [E: claude-hook-stdin.jsonl]

| Event | Fields |
|-------|--------|
| `UserPromptSubmit` | `session_id`, `transcript_path`, `cwd`, `prompt_id`, `permission_mode`, `hook_event_name`, **`prompt`** |
| `SessionStart` | `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `source` |
| `Stop` | common + `permission_mode`, `effort`, `stop_hook_active`, `last_assistant_message`, `background_tasks`, `session_crons` |
| `SessionEnd` | `session_id`, `transcript_path`, `cwd`, `prompt_id`, `hook_event_name`, `reason` |

### Block output that works [E: claude-block-stdout.json]

```json
{"decision":"block","reason":"...","hookSpecificOutput":{"hookEventName":"UserPromptSubmit","suppressOriginalPrompt":true}}
```

- `claude -p` returned [E: claude-sessionend-scrub.txt] `result: "UserPromptSubmit operation blocked by hook:\n<reason>"`, `num_turns: 0`, `duration_api_ms: 0`, cost 0. **No model call.**
- Without `suppressOriginalPrompt`, the block message ends with `Original prompt: <text>`, is printed in the result, and is written to the transcript as `system/informational`. Always set it. [not retained]
- TUI: the text stays in the input box (screen only, not on disk). [not retained]

### Files holding the canary after a block

| Scenario | Result | Evidence |
|----------|--------|----------|
| `-p`, blocked, suppress on | 1 file: `projects/<proj>/<session>.jsonl`, line `type=queue-operation` field `content`; no `history.jsonl` | [E: claude-sessionend-scrub.txt] (`noscrub-blocked` run) |
| `-p`, blocked, suppress off | same + `type=system` `content` | [not retained] (summary: canary-files.txt) |
| TUI, blocked, suppress on | **none** (`history.jsonl` held only `/exit`) | [not retained] (summary: canary-files.txt) |
| `-p`, not blocked | transcript: `queue-operation.content`, `user.message.content`, `api-request-blob.message.content[1].text`, `last-prompt.lastPrompt` (4 hits before scrub) | hit count [E: claude-sessionend-scrub.txt]; field list [not retained] |

`history.jsonl` is written by the TUI only (`-p`: absent [E: claude-sessionend-scrub.txt]). The docs say the text "can still appear" in history; for blocked prompts it did not [not retained].

### Timing facts for the scrubber

- `-p`: at `UserPromptSubmit` the transcript does not exist yet [E: claude-sessionend-scrub.txt]. At `SessionEnd` it exists and holds the canary (`hitsBefore` 1 for a blocked run, 4 unblocked).
- `Stop` does **not** fire after a blocked prompt [not retained]. `SessionStart` and `SessionEnd` do (`-p`; TUI `SessionEnd` after a block was not tested). `SessionEnd` firing is in the raw logs [E: claude-sessionend-scrub.txt, claude-hook-stdin.jsonl].

### `apiKeyHelper` env export (step 4)

Result: **not exported.** Real `Bash` tool call (`env | grep -c AVCANARY_`) driven by a local fake Anthropic API:

| Run | Hook env count (5 events) | Bash result | Request headers at mock |
|-----|--------------------------|-------------|-------------------------|
| `apiKeyHelper` prints canary | 0 | `0` | `x-api-key` and `Authorization: Bearer` = canary |
| control: `ANTHROPIC_API_KEY=canary` | 1 | `1` | same |

So the helper output is used as the credential and is not in the tool environment. Docs say hook processes inherit the parent environment (hooks page), consistent with the control. [E: claude-apikeyhelper-env.txt] (re-run 2026-10-27 as raw output; `env-probe.txt` is the earlier summary.)

### SessionEnd scrub while Claude is alive (fix round 1)

Hook: `spikes/s3-hooks/claude-scrub-hook.mjs` on `SessionEnd` (reads `transcript_path`, writes a temp file in the same dir, renames over the transcript, keeps mode). Driver: `run-sessionend-scrub.sh`. Sandboxed `claude -p` against `mock-anthropic.mjs`, 1 attempt per mode. [E: claude-sessionend-scrub.txt]

| Run | hitsBefore | hitsAfter | Transcript JSONL invalid lines | `--resume <id>` |
|-----|-----------|-----------|--------------------------------|-----------------|
| blocked prompt (`queue-operation` line) | 1 | 0 | 0 of 5 | OK, `is_error=false`, same `session_id`; resumed turns carry no canary |
| unblocked prompt (4 hits) | 4 | 0 | 0 of 22 | OK; resume request body had `[REDACTED:vault]`, no canary |
| control: block hook only, no scrub | - | 1 left (`queue-operation.content`) | 0 | not run |

Whole sandbox after resume: 0 files hold the canary (excluding the hook's own debug log and CLI stdout).

**Limits.** This is `-p`: the hook ran during the process's own shutdown, so it proves the rewrite is accepted and resume works, not that a long-lived TUI session tolerates its transcript being replaced mid-session (an open append handle would keep writing to the old inode). **TUI SessionEnd scrub: untested.** The fallback stays in force regardless: **scrub again at the next `SessionStart`** (and via `agent-vault scan`), when no process holds the file.

### Scrub then resume (harness stopped)

`claude -p --resume <id>` after rewriting the transcript (harness stopped): works for both an unblocked and a blocked session. The unblocked session replayed `[REDACTED:vault]` to the model. The `queue-operation` line of a blocked session is not replayed at all. [not retained] (summary: scrub-resume.txt; the SessionEnd runs above show the same outcome as raw output.)

### MCP

`claude mcp add [-s local|user|project] [-t stdio|sse|http] [-e K=V]... [-H "K: V"]... <name> <commandOrUrl> [args...]`; stdio form `claude mcp add <name> -- <cmd> <args>`. Scope `user` exists. (`--help` only; nothing was added.) [E: mcp-add-help.txt]

## Codex

### Hook config

- `features.hooks` is **stable and on by default** in 0.164.0 (`codex features list`). No flag needed. `codex_hooks` is a deprecated alias. [not retained]
- Config lives in `$CODEX_HOME/hooks.json` [E: codex-hooks.json] (same nesting as Claude's) or inline `[[hooks.<Event>]]` tables in `config.toml`. Project-local `.codex/hooks.json` loads only when the project layer is trusted.
- **Trust is required.** `/hooks` in the TUI lists hooks as "need review" [not retained]; pressing `t` writes this to `config.toml` [E: codex-trust-state.toml]:

```toml
[hooks.state."<abs path>/hooks.json:user_prompt_submit:0:0"]
trusted_hash = "sha256:<hash>"
```

  Key = `<file>:<event_snake_case>:<group index>:<hook index>`. The hash algorithm is not documented, so `install` should not forge it; ask the user to run `/hooks` then `t`, or use `--dangerously-bypass-hook-trust` only for tests.
- Untrusted hooks are **skipped without a visible warning in `codex exec`** and the prompt is sent [E: codex-untrusted-hook.txt]. Editing the command of one hook un-trusted just that hook (it silently stopped running) [not retained].

### Real stdin [E: codex-hook-stdin.jsonl]

| Event | Fields |
|-------|--------|
| `UserPromptSubmit` | `session_id`, `turn_id`, `transcript_path`, `cwd`, `hook_event_name`, `model`, `permission_mode`, **`prompt`** |
| `SessionStart` | `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `model`, `permission_mode`, `source` |

### Block output that works [E: codex-block-stdout.json]

```json
{"decision":"block","reason":"..."}
```

`codex exec` printed `hook: UserPromptSubmit Blocked`; the TUI shows "Blocked by hook" plus the reason. No model call (dead-port provider never contacted). No `suppressOriginalPrompt` equivalent; none needed. [block JSON: E: codex-block-stdout.json; stdout text, TUI text, no-model-call: not retained]

### Files holding the canary after a block

| Scenario | Result | Evidence |
|----------|--------|----------|
| `codex exec`, blocked | **none** (rollout, sqlite, everything) | [not retained] (summary: canary-files.txt) |
| TUI, blocked | `$CODEX_HOME/history.jsonl` only: `{"session_id","ts","text"}` | [E: codex-history-line.json] |
| TUI, blocked, `[history] persistence = "none"` | **none** | [not retained] |
| exec, not blocked | rollout `.jsonl` (`response_item` user message `content`, `event_msg` `item_completed.item`), plus `state_5.sqlite`, `thread_history_1.sqlite` and their `-wal` files | [not retained] (summary: canary-files.txt) |

At hook time the rollout exists and does not yet contain the prompt [E: codex-hook-stdin.jsonl names the path; the exists/hasCanary probe line was not retained]. `Stop` did not fire after a block [not retained].

### Scrub then resume

Rewrote the rollout and both sqlite DBs (same-length replacement, `PRAGMA integrity_check` = ok). `codex exec resume <id>` worked and replayed `[REDACTED:vault]`. **Control:** a corrupted rollout also resumed, so resume success does not prove the file is valid. [not retained] (summary: scrub-resume.txt)

### MCP

`codex mcp add <NAME> (--url <URL> [--bearer-token-env-var <VAR>] | [--env K=V]... -- <COMMAND>...)`. [E: mcp-add-help.txt]

## OpenCode

### Plugin API in 2.1.4 differs from the public docs

- opencode.ai/docs/plugins lists `message.*` events, `tool.execute.before`, `shell.env`, and the installed `@opencode-ai/plugin@1.19.4` types add `chat.message`, `chat.params`, `experimental.chat.messages.transform`. **`chat.message`, `chat.params`, `experimental.chat.messages.transform`, `tool.execute.before` and `shell.env` do not exist as strings in the 2.1.4 binary** (`grep -a -c`: 0 each) [E: opencode-binary-strings.txt]. `message.updated` / `message.part.updated` do appear (2 lines each) but were not seen firing as plugin hooks. A v1-style named-export plugin fails to load: `Plugin must export a default definition with an id and an effect or setup function` [error string present in binary: E: opencode-binary-strings.txt; the failed load itself: not retained].
- Working format [E: opencode-hook-shapes.jsonl shows the hooks firing]: `export default { id, setup(ctx) { ... } }` in `$XDG_CONFIG_HOME/opencode/plugins/*.js` (`spikes/s3-hooks/opencode-plugin/av-spike.js`).
- Hook registration is `ctx.<domain>.hook(name, callback)`. Registration does **not** validate names, so only fired hooks count as real. Names found in the binary:

| Domain | Names (strings from the binary) | Fired in a plain run [E: opencode-hook-shapes.jsonl] |
|--------|-------|----------------------|
| `session` | `context`, `title`, `generate`, `compaction`, `retry`, `model.request`, `http.request`, `http.response`, `experimental.ws.handshake` | `title`, `context`, `model.request`, `http.request`, `http.response` |
| `aisdk` | `sdk`, `language` | no |
| `tool` | `execute.before`, `execute.after` | no (no tool call) |
| `permission` | `evaluate` | no |
| `shell` | name unknown (`shell.hook` exists) | no |

  Also `*.transform` on agent/command/model/provider/integration/mcp/reference/skill/tool/vcs/websearch/worktree, and `event.subscribe`.

### Can a handler mutate or reject the user text before it is sent?

**Yes for the outbound copy, no for the stored copy.**

| Test | Outcome | Evidence |
|------|---------|----------|
| `session.context` draft (`{sessionID, model, system[], messages[{id,role,content[],metadata}], options, agent, tools}`): replace canary | Both model requests (title + main) contained `[REDACTED:vault]`, no canary | draft shape [E: opencode-hook-shapes.jsonl]; request bodies [not retained] |
| `session.context` throw | Main turn aborted with the thrown message; **the separate `session.title` request still carried the canary** unless that hook also guards | [not retained] |
| Where the canary lands anyway | `opencode.db` `session_message.data` (JSON, field `text`), and `opencode.log` for `opencode run "<msg>"` (argv logged) | [not retained] (summary: canary-files.txt) |

No hook runs before persistence. Not tested: whether a plugin can show the user a message (toast) or abort without an error trace in the TUI.

### Paths

Default [E: opencode-paths-sandbox.txt for the `XDG_*` override]: data `~/.local/share/opencode` (`opencode.db` + WAL, `log/`), config `~/.config/opencode`, state `~/.local/state/opencode`, cache `~/.cache/opencode`. `XDG_*` overrides are honored (`evidence/opencode-paths-sandbox.txt`). `debug paths` also reports `tmp /private/tmp/opencode`; tests set `TMPDIR` into the sandbox (effect on that dir not checked).

### Scrub then resume

`opencode.db` same-length replacement + log scrub (`integrity_check` ok). `opencode run --standalone -s <ses_id>` worked and replayed the marker. [not retained] (summary: scrub-resume.txt)

### MCP

`opencode mcp add [--url <URL>] [--header k=v]... [--env k=v]... [--global] <name> [-- <cmd>...]`.

### Operational warning

OpenCode 2.x talks to a shared background service (`opencode serve --service`, 127.0.0.1:49374). Any command without `--standalone` goes there. `opencode debug config` did that once, failed with "port in use", and left the user's service running. **Always pass `--standalone` in tests and in `doctor`.** [not retained]

## What changes in the design

See the updated adapter table in `docs/design.md`. Items for the plan owner (the plan file was not edited):

1. **Task 17 (Claude adapter):** scrub on `SessionEnd` + next `SessionStart` (not `Stop`, not in the hook). Target the `queue-operation.content` line type. `suppressOriginalPrompt: true` is mandatory.
2. **Task 18 (Codex adapter):** install writes `hooks.json`, sets `[history] persistence = "none"` (offer, it disables all history), and **must verify trust**: run a probe canary and check the hook fired. Scrub targets if a prompt slipped through: rollout, `history.jsonl`, `state_5.sqlite`, `thread_history_1.sqlite` (+ `-wal`), same-length.
3. **Task 19 (OpenCode adapter):** v2 plugin with `session.context` and `session.title` guards (redact, never throw only one of the two); scrub `opencode.db`. The `shell.env` row of the design table is unverified for 2.x.
4. **Scrubber:** must be binary-safe and same-length for sqlite, must `grep -a`, and must validate JSONL after rewriting.

## Methods and limits

- Each harness ran with `env -i` plus a sandbox `HOME`/config dir. Model endpoints: Claude → mock Anthropic API (`mock-anthropic.mjs`); Codex → dead port or `mock-400.mjs`; OpenCode → `mock-openai-compat.mjs`. Hook scripts: `claude-hook.mjs`, `codex-hook.mjs`, `env-probe-hook.mjs`, `api-key-helper.sh`.
- TUI tests used a private `tmux -L s3` server.
- **Not tested:** scrubbing while a *long-lived TUI* harness runs (the `-p` SessionEnd case is tested); TUI resume; large pasted blobs (Claude/Codex store pastes by reference); Windows/Linux; Claude TUI `SessionEnd` after a block; OpenCode `shell` hook name; `codex mcp add` / `claude mcp add` / `opencode mcp add` beyond `--help`.
- Disclosure: my first Codex run happened before I knew about hook trust. The hook was skipped and **one fake canary reached `api.openai.com`** (HTTP 401 unauthenticated). No real credential was sent; the prompt was the fake canary. Log not retained; the behavior was reproduced against a local mock (fix round 1).

## Commands run outside the sandbox

Exactly five items: 3 `opencode` invocations (each wrote one line to the real `opencode.log`) and 2 unattributed file changes. No secret was written to a real dir as far as can be told (items 4 and 5 are unattributed); they are listed so the real-dir check can be read honestly. Apart from item 3 (a single `opencode --version`, the `opencode` calls in items 1 and 2 predate this round), fix round 1 ran every harness command sandboxed (`env -i`, `HOME`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `XDG_*` in one temp dir, under `timeout`).

Real `~/.local/share/opencode/log/opencode.log` holds 3 "cli starting" lines from this work, 1 log line each, harmless:

| # | Time (UTC) | Args | Who |
|---|------------|------|-----|
| 1 | 02:58:12Z | `mcp add --help` | earlier spike implementer; was not disclosed before fix round 2 |
| 2 | 03:03:57Z | `mcp add --help` | spike implementer |
| 3 | 15:08:41Z | `--version` | fix round 1, run without the sandbox env |

Unattributed changes (no spike command known to cause them):

4. Real `~/.codex/state_5.sqlite` mtime 02:56Z falls in the spike window. Cause unattributed (a `codex app-server` daemon was running).
5. `~/.claude.json` and `~/.codex/config.toml` changed during the window. Attributed to live sessions, unproven.

Stat-only before/after check, paths sanitized to `~`: [E: real-dirs-check.txt]. `~/.claude/settings.json` and `~/.codex/history.jsonl` are unchanged (mtime and size equal).
