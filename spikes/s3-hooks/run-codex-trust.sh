#!/bin/bash
# Spike S3: Codex skips an UNTRUSTED hook silently and sends the prompt (fail-open). Sandboxed `codex exec` against mock-400.mjs
# (local provider, never api.openai.com). Runs: untrusted hooks.json (expect: hook never runs, mock receives the canary).
# Every codex run: env -i with HOME, CODEX_HOME, CLAUDE_CONFIG_DIR, XDG_* in one fresh temp dir, wrapped in `timeout`.
set -u
S3=$(cd "$(dirname "$0")" && pwd)
SB=$(mktemp -d "${TMPDIR:-/tmp}/av-s3cx.XXXXXX")
mkdir -p "$SB"/{home,cfg,codex,xdg/config,xdg/data,xdg/state,xdg/cache,work}
CANARY="AVCANARY_$(uuidgen | tr A-Z a-z)"
MOCK_LOG=$SB/mock.log AVCANARY_VALUE=$CANARY MOCK_PORT=${MOCK_PORT:-47811} node "$S3/mock-400.mjs" & MP=$!
sleep 1
H='{"hooks":[{"type":"command","command":"node '$S3'/codex-hook.mjs"}]}'
echo '{"hooks":{"SessionStart":['$H'],"UserPromptSubmit":['$H'],"Stop":['$H']}}' > "$SB/codex/hooks.json"
cat > "$SB/codex/config.toml" <<TOML
model = "mock-model"
model_provider = "mock"
[model_providers.mock]
name = "mock"
base_url = "http://127.0.0.1:${MOCK_PORT:-47811}/v1"
wire_api = "responses"
TOML
cd "$SB/work" || exit 1
echo "# codex=$(timeout 30 env -i HOME="$SB/home" CODEX_HOME="$SB/codex" CLAUDE_CONFIG_DIR="$SB/cfg" XDG_CONFIG_HOME="$SB/xdg/config" XDG_DATA_HOME="$SB/xdg/data" XDG_STATE_HOME="$SB/xdg/state" XDG_CACHE_HOME="$SB/xdg/cache" PATH="$(dirname "$(command -v codex)"):/usr/bin:/bin" codex --version 2>&1 | head -1)"
timeout 120 env -i HOME="$SB/home" CODEX_HOME="$SB/codex" CLAUDE_CONFIG_DIR="$SB/cfg" XDG_CONFIG_HOME="$SB/xdg/config" \
  XDG_DATA_HOME="$SB/xdg/data" XDG_STATE_HOME="$SB/xdg/state" XDG_CACHE_HOME="$SB/xdg/cache" TMPDIR="$SB" \
  PATH="$(dirname "$(command -v codex)"):$(dirname "$(command -v node)"):/usr/bin:/bin" AV_HOOK_LOG="$SB/hook.log" \
  codex exec --skip-git-repo-check "please store $CANARY thanks" < /dev/null > "$SB/out.txt" 2> "$SB/err.txt"
echo "codex exec exit=$?"
echo "hook log lines (0 = hook never ran): $(cat "$SB/hook.log" 2>/dev/null | wc -l | tr -d ' ')"
echo "mock log (model endpoint saw the prompt?):"; sed 's/^/  /' "$SB/mock.log" 2>/dev/null | head
echo "stderr/stdout lines mentioning hook/trust/review (0 = no visible warning): $(cat "$SB/err.txt" "$SB/out.txt" | grep -ciE "hook|trust|review")"
echo "stdout head:"; head -c 400 "$SB/out.txt" | sed 's/^/  /'
echo "stderr head:"; head -c 600 "$SB/err.txt" | sed "s/$CANARY/<CANARY>/g" | sed 's/^/  /'
kill $MP 2>/dev/null; rm -rf "$SB"
