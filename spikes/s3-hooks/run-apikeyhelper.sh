#!/bin/bash
# Spike S3 step 4: is apiKeyHelper output exported to the Bash tool / hooks? Sandboxed `claude -p` against mock-anthropic.mjs.
# The mock answers "RUNENVPROBE" with a real Bash tool call (`env | grep -c AVCANARY_`). Runs: helper | control (ANTHROPIC_API_KEY=canary).
# Every claude run: env -i with HOME, CLAUDE_CONFIG_DIR, CODEX_HOME, XDG_* in one fresh temp dir, wrapped in `timeout`.
set -u
S3=$(cd "$(dirname "$0")" && pwd)
CANARY="AVCANARY_$(uuidgen | tr A-Z a-z)"
run() { # $1 = helper|control
  local SB; SB=$(mktemp -d "${TMPDIR:-/tmp}/av-s3key.XXXXXX")
  mkdir -p "$SB"/{home,cfg,codex,xdg/config,xdg/data,xdg/state,xdg/cache,work}
  echo -n "$CANARY" > "$SB/canary.txt"
  local H='{"hooks":[{"type":"command","command":"node '$S3'/env-probe-hook.mjs"}]}'
  local HOOKS='"hooks":{"SessionStart":['$H'],"UserPromptSubmit":['$H'],"PreToolUse":['$H'],"PostToolUse":['$H'],"Stop":['$H']}'
  if [ "$1" = helper ]; then echo '{"apiKeyHelper":"sh '$S3'/api-key-helper.sh",'"$HOOKS"'}'; else echo '{'"$HOOKS"'}'; fi > "$SB/cfg/settings.json"
  MOCK_LOG=$SB/mock.log AVCANARY_VALUE=$CANARY MOCK_PORT=0 node "$S3/mock-anthropic.mjs" > "$SB/port" & local MP=$!
  sleep 1
  local KEY=sk-ant-fake-mock-only; [ "$1" = control ] && KEY=$CANARY
  [ "$1" = helper ] && KEY=
  (cd "$SB/work" && timeout 120 env -i HOME="$SB/home" CLAUDE_CONFIG_DIR="$SB/cfg" CODEX_HOME="$SB/codex" XDG_CONFIG_HOME="$SB/xdg/config" \
    XDG_DATA_HOME="$SB/xdg/data" XDG_STATE_HOME="$SB/xdg/state" XDG_CACHE_HOME="$SB/xdg/cache" TMPDIR="$SB" \
    PATH="$(dirname "$(command -v claude)"):$(dirname "$(command -v node)"):/usr/bin:/bin" \
    ANTHROPIC_BASE_URL="http://127.0.0.1:$(cat "$SB/port")" ${KEY:+ANTHROPIC_API_KEY=$KEY} AV_CANARY_FILE="$SB/canary.txt" AV_ENV_LOG="$SB/env.log" DISABLE_AUTOUPDATER=1 \
    claude -p RUNENVPROBE --allowedTools Bash --output-format json < /dev/null > "$SB/out.json" 2> "$SB/err")
  echo "## run=$1 exit=$? (canary shown as <CANARY>)"
  echo "hook env probe (event,count,keys):"; sed 's/^/  /' "$SB/env.log"
  echo "mock log:"; sed 's/^/  /' "$SB/mock.log"
  kill $MP 2>/dev/null; rm -rf "$SB"
}
echo "# claude=$(claude --version | head -1)"
run helper 2>&1 | grep -v Terminated
run control 2>&1 | grep -v Terminated
