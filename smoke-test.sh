#!/usr/bin/env bash
# Smoke-test the gateway's session classification and mode-switch planning
# WITHOUT any real traffic. It fabricates a CLAUDE_DIR covering every mode, runs
# the deployed binary's `scan` subcommand against it, and asserts the JSON. Then,
# if a gateway is running, it exercises the mode-switch dry-run (which also sends
# no traffic — it only returns the plan).
#
# Usage: ./smoke-test.sh [path-to-binary]   (default: ~/.local/bin/claude-code-proxy-viz)
set -uo pipefail

BIN="${1:-$HOME/.local/bin/claude-code-proxy-viz}"
DASH="${CCP_DASHBOARD:-http://127.0.0.1:3036}"
FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT
CLAUDE_DIR="$FIX/.claude"; PROC="$FIX/proc"
mkdir -p "$CLAUDE_DIR/daemon" "$CLAUDE_DIR/sessions" "$PROC"
PASS=0; FAIL=0
ok(){ echo "  ok   $1"; PASS=$((PASS+1)); }
bad(){ echo "  FAIL $1"; FAIL=$((FAIL+1)); }

# A proxy --settings file: its env.ANTHROPIC_BASE_URL is what marks gateway mode.
PROXY_SETTINGS="$FIX/proxy-settings.json"
printf '{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:18765"}}' > "$PROXY_SETTINGS"

alive(){ mkdir -p "$PROC/$1"; }   # make a pid look running under HOST_PROC

# --- fabricate sessions covering each mode -----------------------------------
python3 - "$CLAUDE_DIR" "$PROXY_SETTINGS" <<'PY'
import json,os,sys
cd,proxy=sys.argv[1],sys.argv[2]
def sess(pid,d): json.dump(d,open(f"{cd}/sessions/{pid}.json","w"))
def job(short,d):
    os.makedirs(f"{cd}/jobs/{short}",exist_ok=True); json.dump(d,open(f"{cd}/jobs/{short}/state.json","w"))
sess(1001,{"pid":1001,"sessionId":"s-native","kind":"bg","name":"native-plain","cwd":"/w/a"})
sess(1002,{"pid":1002,"sessionId":"s-nrc","jobId":"j-nrc","kind":"bg","name":"native-rc","cwd":"/w/b"})
sess(1003,{"pid":1003,"sessionId":"s-gw","jobId":"j-gw","kind":"bg","name":"gateway","cwd":"/w/c"})
sess(1004,{"pid":1004,"sessionId":"s-gwrc","jobId":"j-gwrc","kind":"bg","name":"gateway-flagged-rc","cwd":"/w/d"})
sess(1005,{"pid":1005,"sessionId":"s-lin","jobId":"j-lin","kind":"bg","name":"forked","cwd":"/w/e"})
job("j-done",{"name":"finished-job","state":"done","sessionId":"s-done","cwd":"/w/f","template":"bg","tokens":42,"output":{"result":"all good"}})
json.dump({"workers":{
  "j-nrc":{"startedAt":1,"dispatch":{"launch":{"mode":"resume","sessionId":"parent-nrc","flagArgs":["--remote-control","phoney"]}}},
  "j-gw":{"startedAt":1,"dispatch":{"launch":{"args":["--settings",proxy,"--agent","claude"]}}},
  "j-gwrc":{"startedAt":1,"dispatch":{"launch":{"flagArgs":["--remote-control","x","--settings",proxy]}}},
  "j-lin":{"startedAt":1,"dispatch":{"launch":{"mode":"resume","sessionId":"parent-lin","flagArgs":[]}}}
}},open(f"{cd}/daemon/roster.json","w"))
PY
for p in 1001 1002 1003 1004 1005; do alive $p; done

# --- run the deployed binary's scanner against the fixture (no traffic) -------
echo "== scan classification (offline, synthetic CLAUDE_DIR) =="
SCAN="$(CLAUDE_DIR="$CLAUDE_DIR" HOST_PROC="$PROC" "$BIN" scan 2>/dev/null)"
check(){ # name jq-ish python expr expected
  local name="$1" expr="$2" want="$3"
  local got; got="$(echo "$SCAN" | python3 -c "import sys,json
d=json.load(sys.stdin)
s={x['name']:x for x in d['sessions']}
print($expr)" 2>/dev/null)"
  [ "$got" = "$want" ] && ok "$name ($got)" || bad "$name: got '$got' want '$want'"
}
check "native-plain not managed"        "s['native-plain']['managed']"            "False"
check "native-plain rc_capable"         "s['native-plain']['rc_capable']"         "True"
check "native-rc armed"                 "s['native-rc']['rc']"                    "True"
check "native-rc name (from flagArgs)"  "s['native-rc']['rc_name']"               "phoney"
check "native-rc lineage"               "s['native-rc']['resume_of']"             "parent-nrc"
check "gateway managed"                 "s['gateway']['managed']"                 "True"
check "gateway not rc_capable"          "s['gateway']['rc_capable']"              "False"
check "gateway-flagged-rc honest"       "s['gateway-flagged-rc']['rc']"           "False"
check "forked lineage"                  "s['forked']['resume_of']"                "parent-lin"
check "terminated job shown"            "s['finished-job']['status']"             "done"
check "terminated not live"             "s['finished-job']['live']"               "False"

# --- live dry-run of the mode switch (also traffic-free) ----------------------
echo "== live mode-switch dry-run (no traffic; needs a running gateway) =="
SID="$(curl -sf "$DASH/api/v1/sessions" 2>/dev/null | python3 -c "import sys,json
try: d=json.load(sys.stdin)
except: sys.exit()
print(next((x['session_id'] for x in d['sessions'] if x['live'] and x['session_id']),''))" 2>/dev/null)"
if [ -n "$SID" ]; then
  PLAN="$(curl -sf -H "Origin: $DASH" -H 'content-type: application/json' \
    -X POST "$DASH/api/v1/sessions/$SID/mode" -d '{"mode":"native-rc","dry_run":true}' 2>/dev/null)"
  echo "$PLAN" | grep -q '"--remote-control"' && ok "dry-run plan arms RC" || bad "dry-run plan missing --remote-control"
  echo "$PLAN" | grep -q 'ANTHROPIC_BASE_URL' && ok "dry-run unsets gateway env" || bad "dry-run missing env_unset"
else
  echo "  skip (no running gateway / live session at $DASH)"
fi

echo "== $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
