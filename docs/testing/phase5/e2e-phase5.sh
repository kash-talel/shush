#!/usr/bin/env bash
# Phase 5a e2e. Usage: e2e-phase5.sh <scratchpad dir>
set -uo pipefail
cd "$1"
D="node cdp.mjs"; W="powershell -NoProfile -ExecutionPolicy Bypass -File win.ps1"
pass=0; fail=0
ok()   { echo "PASS  $1"; pass=$((pass+1)); }
bad()  { echo "FAIL  $1 ($2)"; fail=$((fail+1)); }
check() { if [ "$($D eval "!!($2)")" = "true" ]; then ok "$1"; else bad "$1" "predicate false"; fi; }
waitfor() { $D wait "$1" "${2:-15000}" >/dev/null || echo "TIMEOUT waiting for: $1"; }
KEY=$(powershell -NoProfile -Command "(Get-Item '$(cygpath -w "$1/e2e/usb/vault.key")').FullName")

unlock() {
  $D click "#unseal" >/dev/null; $D fill "#master-password" "Tactical-Vault-2026" >/dev/null
  $D click "text:browse" >/dev/null; sleep 2
  powershell -NoProfile -ExecutionPolicy Bypass -File dialog.ps1 -Title "Select keyfile" -Path "$KEY" >/dev/null
  waitfor "document.body.textContent.includes('KEYFILE ATTACHED')"
  $D click "button[type=submit]" >/dev/null
  waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
}

echo "--- screen-capture protection"
aff=$($W affinity | tr -d '\r')
[ "$aff" = "0x11" ] && ok "WDA_EXCLUDEFROMCAPTURE set on main window" || bad "display affinity" "got $aff"

echo "--- auto-lock on Windows session lock (real WM_WTSSESSION_CHANGE)"
unlock
check "unlocked before trigger" "document.querySelector('footer').textContent.includes('UNLOCKED')"
$W post-lock >/dev/null
waitfor "document.querySelector('#master-password')" 10000
check "UI back on unlock screen" "document.querySelector('#master-password')"
check "reason shown to user" "document.body.textContent.includes('AUTO-LOCKED') && document.body.textContent.includes('Windows was locked')"
check "status bar says LOCKED" "document.querySelector('footer').textContent.includes('LOCKED') && !document.querySelector('footer').textContent.includes('UNLOCKED')"
$D shot shots/p5-01-autolocked.png >/dev/null
$W post-lock >/dev/null; sleep 1
check "lock event while already locked is harmless" "document.querySelector('#master-password')"
unlock
check "re-unlock works and clears the notice" "document.querySelector('nav') && !document.body.textContent.includes('AUTO-LOCKED')"

echo "--- close hides to tray, process stays alive"
$W close >/dev/null; sleep 1
vis=$($W visible | tr -d '\r')
[ "$vis" = "False" ] && ok "window hidden on close" || bad "window hidden on close" "visible=$vis"
pgrep -f shush >/dev/null 2>&1; alive=$(powershell -NoProfile -Command "@(Get-Process shush -ErrorAction SilentlyContinue).Count")
[ "$alive" -ge 1 ] && ok "process still running in tray" || bad "process alive" "count=$alive"
check "vault stays unlocked while hidden (auto-lock guards it)" "document.querySelector('footer').textContent.includes('UNLOCKED')"

echo "--- second launch focuses the existing instance (single-instance)"
before=$(powershell -NoProfile -Command "@(Get-Process shush).Count")
powershell -NoProfile -Command "Start-Process '$(cygpath -w /c/Users/kash_talel/orca/projects/shush/src-tauri/target/debug/shush.exe)'" >/dev/null
sleep 4
after=$(powershell -NoProfile -Command "@(Get-Process shush).Count")
vis=$($W visible | tr -d '\r')
[ "$after" = "$before" ] && ok "no second process left running" || bad "single instance" "before=$before after=$after"
[ "$vis" = "True" ] && ok "existing window shown again" || bad "window re-shown" "visible=$vis"

echo "=== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
