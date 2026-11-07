#!/usr/bin/env bash
# Phase 7a e2e (first-run onboarding). Usage: e2e-phase7a.sh <scratchpad dir> <expected browser ids, comma-separated>
set -uo pipefail
cd "$1"; EXPECT="$2"
D="node cdp.mjs"; DLG="powershell -NoProfile -ExecutionPolicy Bypass -File dialog.ps1"
pass=0; fail=0
check() { if [ "$($D eval "!!($2)")" = "true" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
waitfor() { $D wait "$1" "${2:-15000}" >/dev/null || echo "TIMEOUT waiting for: $1"; }
body="document.body.textContent"
DIR=$(powershell -NoProfile -Command "(Get-Item '$(cygpath -w "$1/e2e7")').FullName" | tr -d '\r')

echo "--- create a fresh vault"
$D fill "#new-password" "Onboarding-Test-2026" >/dev/null
$D fill "#confirm-password" "Onboarding-Test-2026" >/dev/null
$D click "input[type=checkbox]" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "$body.includes('BRING_YOUR_PASSWORDS')" 30000
check "onboarding shown right after creation" "$body.includes('BRING_YOUR_PASSWORDS')"
check "skip offered before any import" "$body.includes('SKIP FOR NOW')"

echo "--- browser detection matches this PC ($EXPECT)"
IDS=$($D eval "[...document.querySelectorAll('[aria-label=\"Browsers found on this PC\"] li')].map(li => li.textContent).join('|')")
echo "      listed: $IDS"
for id in ${EXPECT//,/ }; do
  case $id in chrome) name="Google Chrome";; edge) name="Microsoft Edge";; brave) name="Brave";; firefox) name="Mozilla Firefox";; esac
  echo "$IDS" | grep -q "$name" && { echo "PASS  $name listed"; pass=$((pass+1)); } || { echo "FAIL  $name missing"; fail=$((fail+1)); }
done
count=$($D eval "document.querySelectorAll('[aria-label=\"Browsers found on this PC\"] li').length")
want=$(echo "$EXPECT" | tr ',' '\n' | grep -c .)
[ "$count" = "$want" ] && { echo "PASS  no extra browsers listed ($count)"; pass=$((pass+1)); } || { echo "FAIL  listed $count, expected $want"; fail=$((fail+1)); }
$D shot shots/p7a-01-onboarding.png >/dev/null

echo "--- import a CSV from the onboarding screen"
printf 'name,url,username,password\r\nonboard.test,https://onboard.test,dana,ob-pw\r\n' > "$1/e2e7/export.csv"
$D click "text:Choose a .csv export" >/dev/null; sleep 2
$DLG -Title "Choose a password export (CSV)" -Path "$DIR\\export.csv" >/dev/null
waitfor "$body.includes('IMPORT 1 NEW')" 20000
$D click "text:IMPORT 1 NEW" >/dev/null
waitfor "$body.includes('Imported 1 item')" 20000
check "import works inside onboarding" "$body.includes('Imported 1 item')"
check "primary action switches to OPEN MY VAULT" "$body.includes('OPEN MY VAULT')"
$D click "text:Overwrite & delete the CSV" >/dev/null
waitfor "$body.includes('overwritten and deleted')"
[ ! -e "$1/e2e7/export.csv" ] && { echo "PASS  CSV shredded"; pass=$((pass+1)); } || { echo "FAIL  CSV still on disk"; fail=$((fail+1)); }

echo "--- continue to the vault"
$D click "text:OPEN MY VAULT" >/dev/null
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')"
check "dashboard shows the imported login" "[...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('onboard.test'))"

echo "--- onboarding is first-run only"
$D eval "window.dispatchEvent(new KeyboardEvent('keydown',{key:'l',ctrlKey:true})), 1" >/dev/null
waitfor "document.querySelector('#master-password')"
$D fill "#master-password" "Onboarding-Test-2026" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
check "normal unlock goes straight to the dashboard" "document.querySelector('nav') && !$body.includes('BRING_YOUR_PASSWORDS')"

echo "=== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
