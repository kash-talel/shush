#!/usr/bin/env bash
# Phase 7b e2e (issue #53): the MV3 extension in a real Edge, against the real shush-host.exe.
# Drives the app and a headless Edge over CDP only; no desktop keyboard or mouse input.
#
# Usage: e2e-phase7b.sh <scratch dir>
#   Start the debug app first (docs/testing/README.md) on a FRESH scratch vault (onboarding screen),
#   with CDP_PORT set to its CDP port and SHUSH_NMH_REGISTRY_ROOT unset: browsers only read the real
#   HKCU\Software\...\NativeMessagingHosts keys, so this run writes them. It refuses to start if a
#   com.shush.vault key already exists (an installed shush that has browser support on), and removes
#   the keys again on exit, whatever happens.
#   Env: EDGE_PORT (default 9333), PAGE_PORT (default 8765), EDGE (path to msedge.exe).
#
# Covers:
# 1. Settings toggle writes the three HKCU keys; manifests pin the extension id and the host path.
# 2. Edge loads extension/ unpacked under exactly the pinned id.
# 3. The popup reaches shush through the registered shush-host.exe ("Connected").
# 4. Pairing with the code from Settings: both sides hold the pairing.
# 5. Inline fill on http://localhost:<PAGE_PORT> fills username and password.
# 6. No fill on another origin (http://127.0.0.1:<PAGE_PORT>).
# 7. No fill while shush is locked; fill again after unlock (pairing persisted in the vault).
# 8. Revoke in shush: the extension is refused and wipes its stored key.
# 9. Unticking the toggle removes the keys and manifests.

set -uo pipefail
WORK="${1:?usage: e2e-phase7b.sh <scratch dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
mkdir -p "$WORK"
export EDGE_PORT="${EDGE_PORT:-9333}"
PAGE_PORT="${PAGE_PORT:-8765}"
EDGE="${EDGE:-/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe}"
EXT_ID="kmcbplfcpijmfohfojkajnmejadkcipe"
PW="Phase7b-Browser-2026"
D="node $HERE/../phase8a/cdp.mjs"
E="node $HERE/edge.mjs"
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
check() { if [ "$($D eval "!!($2)")" = "true" ]; then ok "$1"; else bad "$1"; fi; }
waitfor() { $D wait "$1" "${2:-20000}" >/dev/null || echo "TIMEOUT: $1"; }
invoke() { $D eval "window.__TAURI_INTERNALS__.invoke($1)"; }
ps() { powershell -NoProfile -Command "$1" | tr -d '\r'; }
keys_present() {
  ps "\$n=0; foreach (\$k in 'Google\\Chrome','Microsoft\\Edge','Mozilla') { if (Test-Path \"HKCU:\\Software\\\$k\\NativeMessagingHosts\\com.shush.vault\") { \$n++ } }; \$n"
}
fill_result() { $E eval "$1" "document.getElementById('u').value+'|'+document.getElementById('p').value" | tr -d '"'; }
expected='e2e-user|Fill-Me-9!xyz'
empty='|'

if [ "$(keys_present)" != "0" ]; then
  echo "ABORT: a com.shush.vault native-messaging key already exists; this run would overwrite it."
  exit 2
fi

PROFILE="$(cygpath -w "$WORK")\\edge-profile"
cleanup() {
  invoke "'set_browser_support',{enabled:false}" >/dev/null 2>&1
  for k in 'Google\Chrome' 'Microsoft\Edge' 'Mozilla'; do
    reg delete "HKCU\\Software\\$k\\NativeMessagingHosts\\com.shush.vault" /f >/dev/null 2>&1
  done
  ps "Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | Where-Object { \$_.CommandLine -like '*$(basename "$WORK")*edge-profile*' } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force -ErrorAction SilentlyContinue }" >/dev/null
  [ -n "${PAGE_PID:-}" ] && kill "$PAGE_PID" 2>/dev/null
}
trap cleanup EXIT

echo "--- vault with one login for http://localhost:$PAGE_PORT"
$D fill "#new-password" "$PW" >/dev/null
$D fill "#confirm-password" "$PW" >/dev/null
$D click "input[type=checkbox]" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.body.innerText.includes('SKIP FOR NOW')" 60000
# Before leaving the import screen, so the item list loads with it.
invoke "'create_item',{kind:'login',draft:{title:'Local test',username:'e2e-user',password:'Fill-Me-9!xyz',url:'http://localhost:$PAGE_PORT',totp:null,notes:'',content:'',favorite:false,tags:[],folder_id:null}}" >/dev/null
$D click "text:SKIP FOR NOW" >/dev/null
waitfor "document.body.innerText.includes('Local test')"

echo "--- 1. Settings toggle registers the host"
$D click "text:Backup & import" >/dev/null
waitfor "document.body.innerText.includes('Allow browsers')"
$D click "input[type=checkbox]" >/dev/null
waitfor "document.querySelector('input[type=checkbox]').checked"
[ "$(keys_present)" = "3" ] && ok "three HKCU keys written" || bad "three HKCU keys written"
manifest=$(ps "Get-Content ((Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.shush.vault').'(default)') -Raw")
echo "$manifest" | grep -q "chrome-extension://$EXT_ID/" && ok "Edge manifest pins the extension id" || bad "Edge manifest pins the extension id"
echo "$manifest" | grep -q 'shush-host.exe' && ok "Edge manifest points at shush-host.exe" || bad "Edge manifest points at shush-host.exe"

echo "--- 2. Edge with the unpacked extension"
node "$HERE/page.mjs" "$PAGE_PORT" > "$WORK/page.log" 2>&1 &
PAGE_PID=$!
EXT="$(cygpath -w "$REPO/extension")"
"$EDGE" --headless=new --user-data-dir="$PROFILE" --remote-debugging-port="$EDGE_PORT" \
  --remote-debugging-address=127.0.0.1 --no-first-run --no-default-browser-check \
  --load-extension="$EXT" --disable-extensions-except="$EXT" about:blank > "$WORK/edge.log" 2>&1 &
for _ in $(seq 1 30); do $E list 2>/dev/null | grep -q "$EXT_ID" && break; sleep 1; done
$E list | grep -q "service_worker chrome-extension://$EXT_ID/background.js" \
  && ok "extension loaded under the pinned id" || bad "extension loaded under the pinned id"

echo "--- 3. popup reaches shush"
$E open "http://localhost:$PAGE_PORT/"
sleep 2
# The first openPopup() after launch can report success without showing anything: retry.
for _ in 1 2 3 4 5; do
  $E eval "$EXT_ID/background.js" "chrome.action.openPopup().then(()=>1,()=>0)" >/dev/null
  sleep 2
  $E list | grep -q "$EXT_ID/popup.html" && break
done
popup() { $E eval popup.html "new Promise(r=>setTimeout(r,${1:-500})).then(()=>document.body.innerText)"; }
popup 1500 | grep -q "Connected" && ok "popup: connected to shush" || bad "popup: connected to shush"

echo "--- 4. pairing"
$D click "text:SHOW PAIRING CODE" >/dev/null
waitfor "/\\b[A-Z2-7]{4}-[A-Z2-7]{4}\\b/.test(document.body.innerText)"
CODE=$($D eval "document.body.innerText.match(/\\b[A-Z2-7]{4}-[A-Z2-7]{4}\\b/)[0]" | tr -d '"')
$E eval popup.html "document.getElementById('code').value='$CODE'; document.getElementById('pair-go').click(); 1" >/dev/null
popup 4000 | grep -q "Paired" && ok "popup: paired" || bad "popup: paired"
[ "$($E eval "$EXT_ID/background.js" "chrome.storage.local.get('pairing').then(v=>!!v.pairing?.key)")" = "true" ] \
  && ok "extension stored its pairing" || bad "extension stored its pairing"
check "shush lists the paired browser" "document.body.innerText.includes('REVOKE')"

echo "--- 5. fill on the item's origin"
$E fill "localhost:$PAGE_PORT"
[ "$(fill_result "localhost:$PAGE_PORT")" = "$expected" ] && ok "username and password filled" || bad "username and password filled"

echo "--- 6. no fill on another origin"
$E open "http://127.0.0.1:$PAGE_PORT/"
sleep 2
$E fill "127.0.0.1:$PAGE_PORT"
[ "$(fill_result "127.0.0.1:$PAGE_PORT")" = "$empty" ] && ok "127.0.0.1 gets nothing" || bad "127.0.0.1 gets nothing"

reload_page() { $E eval "localhost:$PAGE_PORT" "location.reload(),1" >/dev/null; sleep 2; }

echo "--- 7. locked, then unlocked"
invoke "'lock'" >/dev/null
reload_page
$E fill "localhost:$PAGE_PORT"
[ "$(fill_result "localhost:$PAGE_PORT")" = "$empty" ] && ok "no fill while locked" || bad "no fill while locked"
$D eval "location.reload(),1" >/dev/null
waitfor "document.querySelector('#unseal,#master-password')"
$D eval "document.querySelector('#unseal')?.click(),1" >/dev/null
waitfor "document.querySelector('#master-password')"
$D fill "#master-password" "$PW" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.body.innerText.includes('Local test')" 60000
reload_page
$E fill "localhost:$PAGE_PORT"
[ "$(fill_result "localhost:$PAGE_PORT")" = "$expected" ] && ok "fill after unlock (pairing persisted)" || bad "fill after unlock (pairing persisted)"

echo "--- 8. revoke"
$D click "text:Backup & import" >/dev/null
waitfor "document.body.innerText.includes('REVOKE')"
$D click "text:REVOKE" >/dev/null
waitfor "!document.body.innerText.includes('REVOKE')"
reload_page
$E fill "localhost:$PAGE_PORT"
[ "$(fill_result "localhost:$PAGE_PORT")" = "$empty" ] && ok "revoked browser gets nothing" || bad "revoked browser gets nothing"
[ "$($E eval "$EXT_ID/background.js" "chrome.storage.local.get('pairing').then(v=>!v.pairing)")" = "true" ] \
  && ok "extension wiped its key" || bad "extension wiped its key"

echo "--- 9. untick removes the registration"
$D click "input[type=checkbox]" >/dev/null
waitfor "!document.querySelector('input[type=checkbox]').checked"
[ "$(keys_present)" = "0" ] && ok "keys removed" || bad "keys removed"

echo
echo "phase 7b: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
