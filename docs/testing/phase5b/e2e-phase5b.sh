#!/usr/bin/env bash
# Phase 5b e2e (Spotlight). Usage: e2e-phase5b.sh <scratchpad dir>   (vault: e2e7, has login "Jira")
set -uo pipefail
cd "$1"
M="node cdp.mjs"; SP="env CDP_WINDOW=spotlight node cdp.mjs"
WIN="powershell -NoProfile -ExecutionPolicy Bypass -File win.ps1"
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1 ($2)"; fail=$((fail+1)); }
mcheck() { if [ "$($M eval "!!($2)")" = "true" ]; then ok "$1"; else bad "$1" "main"; fi; }
scheck() { if [ "$($SP eval "!!($2)")" = "true" ]; then ok "$1"; else bad "$1" "spotlight"; fi; }
mwait() { $M wait "$1" "${2:-15000}" >/dev/null || echo "TIMEOUT (main): $1"; }
swait() { $SP wait "$1" "${2:-15000}" >/dev/null || echo "TIMEOUT (spotlight): $1"; }
spot_visible() { $WIN spot-visible | tr -d '\r'; }
emit_open() { $M eval "window.__TAURI_INTERNALS__.invoke('plugin:event|emit', { event: 'spotlight-open', payload: { context: $1 } }).then(() => 1)" >/dev/null; }

echo "--- global hotkey is owned by shush"
r=$($WIN hotkey-owned | tr -d '\r')
[ "$r" = "1409" ] && ok "Ctrl+Alt+Space already registered (by shush)" || bad "hotkey ownership" "got $r"

echo "--- unlock main, open Spotlight from the sidebar button"
if [ "$($M eval "!!document.querySelector('#master-password')")" = "true" ]; then
  $M fill "#master-password" "Onboarding-Test-2026" >/dev/null
  $M click "button[type=submit]" >/dev/null
fi
mwait "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
mcheck "sidebar shows the hotkey" "document.body.textContent.includes('CTRL+ALT+SPACE')"
[ "$(spot_visible)" = "False" ] && ok "Spotlight starts hidden (prewarmed)" || bad "starts hidden" "visible"
$M click "text:Quick search" >/dev/null; sleep 1
[ "$(spot_visible)" = "True" ] && ok "Quick search shows the Spotlight window" || bad "show" "hidden"
swait "document.querySelectorAll('[role=option]').length >= 1"
scheck "Spotlight lists logins" "[...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('Jira'))"
$SP shot shots/p5b-01-spotlight.png >/dev/null

echo "--- search filters"
$SP fill "[aria-label=\"Search logins\"]" "zzzz" >/dev/null
scheck "no-match message" "document.body.textContent.includes('No matching logins')"
$SP fill "[aria-label=\"Search logins\"]" "jra" >/dev/null
scheck "fuzzy subsequence finds Jira" "document.querySelectorAll('[role=option]').length === 1 && document.querySelector('[aria-selected=true]').textContent.includes('Jira')"

echo "--- Esc hides"
$SP eval "window.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape'})), 1" >/dev/null; sleep 1
[ "$(spot_visible)" = "False" ] && ok "Esc hides Spotlight" || bad "Esc" "still visible"

echo "--- active-window context pre-selects (never auto-types)"
emit_open "'Jira board - Sprint 42'"
swait "document.body.textContent.includes('Matched the active window')"
scheck "context chip shown and Jira pre-selected" "document.body.textContent.includes('Jira board - Sprint 42') && document.querySelector('[aria-selected=true]')?.textContent.includes('Jira')"
emit_open "'Totally unrelated window'"
sleep 1
scheck "unrelated title pre-selects nothing" "!document.body.textContent.includes('Matched the active window')"

echo "--- locking the vault locks Spotlight"
$M eval "window.dispatchEvent(new KeyboardEvent('keydown',{key:'l',ctrlKey:true})), 1" >/dev/null
mwait "document.querySelector('#master-password')"
emit_open "null"
swait "document.body.textContent.includes('VAULT_LOCKED')"
scheck "Spotlight shows VAULT_LOCKED and hides logins" "document.body.textContent.includes('VAULT_LOCKED') && document.querySelectorAll('[role=option]').length === 0"

echo "=== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
