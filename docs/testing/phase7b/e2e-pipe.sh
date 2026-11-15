#!/usr/bin/env bash
# Pipe listener e2e (issue #153): the named-pipe server, the shush-host.exe image check, the rate
# limit, the connection cap and the squat warning, against the real debug app and the real
# shush-host.exe. CDP and pipe I/O only; no desktop keyboard or mouse input. Touches no browser
# registry keys. Pairing and fill through the host are covered by e2e-phase7b.sh.
#
# Usage: e2e-pipe.sh <scratch dir>
#   Build first:   cargo build --manifest-path src-tauri/Cargo.toml --bins
#   Run Vite:      (cd src && npx vite --port 1420 --strictPort)       # the debug app loads it
#   Env: CDP_PORT (dot-source .claude/scripts/issue-env.ps1 sets it),
#        SHUSH_EXE (default src-tauri/target/debug/shush.exe; shush-host.exe must sit beside it).
#   Close an installed shush first: the pipe name is per user, so a running one owns it. The
#   script aborts if the pipe already exists. It starts and stops the app itself, on a scratch
#   vault under <scratch dir>.
#
# Covers:
# 1. A client that is not shush-host.exe is closed without an answer (image check).
# 2. The real shush-host.exe is answered.
# 3. Rate limit: 30 requests per second per connection, then it is cut.
# 4. Connection cap: 8 live connections, the 9th is dropped; a slot frees when one closes.
# 5. Squatted pipe name: the app reports not serving, with the warning text; the host refuses a
#    pipe not served by shush.exe.

set -uo pipefail
WORK="${1:?usage: e2e-pipe.sh <scratch dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
SHUSH_EXE="${SHUSH_EXE:-$REPO/src-tauri/target/debug/shush.exe}"
HOST_EXE="$(dirname "$SHUSH_EXE")/shush-host.exe"
EXE_WIN="$(cygpath -w "$SHUSH_EXE")"
HOST_WIN="$(cygpath -w "$HOST_EXE")"
D="node $HERE/../phase8a/cdp.mjs"
PW="Pipe-E2E-2026-pass"
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
waitfor() { $D wait "$1" "${2:-20000}" >/dev/null || echo "TIMEOUT: $1"; }
invoke() { $D eval "window.__TAURI_INTERNALS__.invoke($1)"; }
ps() { powershell -NoProfile -Command "$1" | tr -d '\r'; }
[ -f "$SHUSH_EXE" ] && [ -f "$HOST_EXE" ] || { echo "ABORT: build the bins first ($SHUSH_EXE, $HOST_EXE)"; exit 2; }
mkdir -p "$WORK"
export SHUSH_VAULT_PATH="$(cygpath -w "$WORK")\\vault.shush"
export SHUSH_NO_SINGLE_INSTANCE=1
export WEBVIEW2_USER_DATA_FOLDER="$(cygpath -w "$WORK")\\webview2"
export WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--remote-debugging-port=${CDP_PORT:-9222} --remote-debugging-address=127.0.0.1"

pipe_exists() { ps "[IO.Directory]::GetFiles('\\\\.\\pipe\\') -match 'shush-S-1-' | Select-Object -First 1"; }
# Stops only the processes started from this checkout's build.
stop_app() {
  ps "Get-CimInstance Win32_Process | Where-Object { \$_.ExecutablePath -ieq '$EXE_WIN' -or \$_.ExecutablePath -ieq '$HOST_WIN' } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }" >/dev/null
}
cleanup() { [ -n "${SQUAT_PID:-}" ] && kill "$SQUAT_PID" 2>/dev/null; stop_app; }
trap cleanup EXIT

if [ -n "$(pipe_exists)" ]; then
  echo "ABORT: a shush pipe already exists (an installed or other shush is running). Close it first."
  exit 2
fi

launch() {
  "$SHUSH_EXE" > "$WORK/app.log" 2>&1 &
  # cdp.mjs fails at once while the port is closed or the page is still about:blank: retry.
  for _ in $(seq 1 60); do
    [ "$($D eval "document.body.innerText.length > 0" 2>/dev/null)" = "true" ] && break
    sleep 1
  done
}

echo "--- app with a fresh scratch vault"
launch
$D fill "#new-password" "$PW" >/dev/null
$D fill "#confirm-password" "$PW" >/dev/null
$D click "input[type=checkbox]" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.body.innerText.includes('SKIP FOR NOW')" 60000
$D click "text:SKIP FOR NOW" >/dev/null
sleep 2
invoke "'bridge_state'" | grep -q '"serving":true' \
  && ok "app reports the pipe is serving" || bad "app reports the pipe is serving"

echo "--- 1-4. image check, rate limit, connection cap"
node "$HERE/pipe-probe.mjs" serve "$HOST_WIN" | tee "$WORK/serve.log"
pass=$((pass + $(grep -c '^PASS' "$WORK/serve.log"))); fail=$((fail + $(grep -c '^FAIL' "$WORK/serve.log")))

echo "--- 5. squatted pipe name"
stop_app
sleep 1
node "$HERE/pipe-probe.mjs" squat > "$WORK/squat.log" 2>&1 &
SQUAT_PID=$!
sleep 2
grep -q squatting "$WORK/squat.log" && ok "squatter holds the pipe name" || bad "squatter holds the pipe name"
launch
waitfor "document.querySelector('#unseal,#master-password')" 60000
$D eval "document.querySelector('#unseal')?.click(),1" >/dev/null
waitfor "document.querySelector('#master-password')"
$D fill "#master-password" "$PW" >/dev/null
$D click "button[type=submit]" >/dev/null
sleep 4
info=$(invoke "'bridge_state'")
echo "$info" | grep -q '"serving":false' && ok "squatted: app reports not serving" || bad "squatted: app reports not serving"
echo "$info" | grep -q "Another program is using shush's browser pipe" \
  && ok "squatted: warning text is shown" || bad "squatted: warning text is shown"
node "$HERE/pipe-probe.mjs" refuse "$HOST_WIN" | tee "$WORK/refuse.log"
pass=$((pass + $(grep -c '^PASS' "$WORK/refuse.log"))); fail=$((fail + $(grep -c '^FAIL' "$WORK/refuse.log")))

echo "--- $pass passed, $fail failed"
[ "$fail" = 0 ]
