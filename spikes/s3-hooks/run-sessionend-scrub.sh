#!/bin/bash
# Spike S3 fix 4: sandboxed `claude -p` against mock-anthropic.mjs with claude-scrub-hook.mjs on SessionEnd.
# usage: run-sessionend-scrub.sh blocked|unblocked|noscrub-blocked   (noscrub-blocked = control: UserPromptSubmit block hook only)
# Every claude run: env -i with HOME, CLAUDE_CONFIG_DIR, CODEX_HOME, XDG_* all inside one fresh temp dir, wrapped in `timeout`.
set -u
S3=$(cd "$(dirname "$0")" && pwd)
MODE=${1:-blocked}
SB=$(mktemp -d "${TMPDIR:-/tmp}/av-s3fix4.XXXXXX")
mkdir -p "$SB"/{home,cfg,codex,xdg/config,xdg/data,xdg/state,xdg/cache,work}
CANARY="AVCANARY_$(uuidgen | tr A-Z a-z)"
LOG=$SB/hook.log
MLOG=$SB/mock.log
SCRUB='{"type":"command","command":"node '$S3'/claude-scrub-hook.mjs"}'
BLOCK='{"type":"command","command":"node '$S3'/claude-hook.mjs"}'
case $MODE in
  blocked) echo '{"hooks":{"SessionEnd":[{"hooks":['"$SCRUB"']}],"UserPromptSubmit":[{"hooks":['"$BLOCK"']}]}}' ;;
  unblocked) echo '{"hooks":{"SessionEnd":[{"hooks":['"$SCRUB"']}]}}' ;;
  noscrub-blocked) echo '{"hooks":{"UserPromptSubmit":[{"hooks":['"$BLOCK"']}]}}' ;;
esac > "$SB/cfg/settings.json"
MOCK_LOG=$MLOG AVCANARY_VALUE=$CANARY MOCK_PORT=0 node "$S3/mock-anthropic.mjs" > "$SB/port" & MP=$!
sleep 1
PORT=$(cat "$SB/port")
SBENV=(HOME="$SB/home" CLAUDE_CONFIG_DIR="$SB/cfg" CODEX_HOME="$SB/codex" XDG_CONFIG_HOME="$SB/xdg/config"
  XDG_DATA_HOME="$SB/xdg/data" XDG_STATE_HOME="$SB/xdg/state" XDG_CACHE_HOME="$SB/xdg/cache" TMPDIR="$SB"
  PATH="$(dirname "$(command -v claude)"):$(dirname "$(command -v node)"):/usr/bin:/bin"
  ANTHROPIC_BASE_URL="http://127.0.0.1:$PORT" ANTHROPIC_API_KEY=sk-ant-fake-mock-only AV_HOOK_LOG="$LOG"
  DISABLE_AUTOUPDATER=1)
cd "$SB/work" || exit 1
SID=
lines() { # summarize transcript lines that hold the canary: type/subtype/top-level field
  node -e '
    const [f, c] = process.argv.slice(1);
    let bad = 0, n = 0;
    for (const l of require("fs").readFileSync(f, "utf8").split("\n")) {
      if (!l.trim()) continue;
      n++;
      let o; try { o = JSON.parse(l); } catch { bad++; continue; }
      if (l.includes(c)) console.log(`  canary in line type=${o.type}${o.subtype ? "/" + o.subtype : ""}${o.operation ? " op=" + o.operation : ""} fields=${Object.keys(o).filter((k) => JSON.stringify(o[k]).includes(c)).join(",")}`);
    }
    console.log(`  lines=${n} invalid_json_lines=${bad}`);' "$1" "$CANARY"
}
echo "# mode=$MODE claude=$(timeout 30 env -i "${SBENV[@]}" claude --version 2>/dev/null | head -1)"
timeout 120 env -i "${SBENV[@]}" claude -p "please store $CANARY thanks" --output-format json < /dev/null > "$SB/out1.json" 2> "$SB/err1"
echo "run1 exit=$? result=$(node -e 'const j=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));console.log(JSON.stringify({is_error:j.is_error,num_turns:j.num_turns,duration_api_ms:j.duration_api_ms,result:String(j.result).slice(0,120)}))' "$SB/out1.json")"
SID=$(node -e 'console.log(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).session_id)' "$SB/out1.json")
T=$(ls "$SB"/cfg/projects/*/"$SID".jsonl)
echo "hook log (scrub + transcript-at-hook-time):"; grep -E '"at": ?"(scrub-hook|transcript-at-hook-time)"' "$LOG" | sed 's/^/  /'
echo "transcript after run1 (canary hits=$(grep -aoc "$CANARY" "$T")):"; lines "$T"
echo "history.jsonl present: $([ -e "$SB/cfg/history.jsonl" ] && echo yes || echo no)"
if [ "$MODE" != noscrub-blocked ]; then
  : > "$MLOG"
  timeout 120 env -i "${SBENV[@]}" claude -p "continue please" --resume "$SID" --output-format json < /dev/null > "$SB/out2.json" 2> "$SB/err2"
  echo "run2 (--resume) exit=$? $(node -e 'const j=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));console.log(JSON.stringify({is_error:j.is_error,session_id_same:j.session_id===process.argv[2],num_turns:j.num_turns,result:String(j.result).slice(0,40)}))' "$SB/out2.json" "$SID")"
  echo "mock requests on resume: n=$(grep -c '"url"' "$MLOG") withCanary=$(grep -c '"bodyHasCanary":true' "$MLOG") withMarker=$(grep -c '"bodyHasRedacted":true' "$MLOG")"
  echo "transcript after run2 (canary hits=$(grep -aoc "$CANARY" "$T")):"; lines "$T"
  echo "files in sandbox holding canary, excluding hook/mock logs and CLI stdout: $(grep -rlaF "$CANARY" "$SB" --exclude=hook.log --exclude=mock.log --exclude='out*.json' --exclude=err1 --exclude=err2 | wc -l | tr -d ' ')"
fi
kill $MP 2>/dev/null
rm -rf "$SB"
