#!/usr/bin/env bash
# Phase 6b e2e (CSV migration) over CDP. Usage: e2e-phase6b.sh <scratchpad dir>
set -uo pipefail
cd "$1"
D="node cdp.mjs"; DLG="powershell -NoProfile -ExecutionPolicy Bypass -File dialog.ps1"
pass=0; fail=0
check() { if [ "$($D eval "!!($2)")" = "true" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
waitfor() { $D wait "$1" "${2:-15000}" >/dev/null || echo "TIMEOUT waiting for: $1"; }
E2E=$(powershell -NoProfile -Command "(Get-Item '$(cygpath -w "$1/e2e")').FullName" | tr -d '\r')
KEY="$E2E\\usb\\vault.key"; CSV="$E2E\\chrome-passwords.csv"
body="document.body.textContent"
opts="[...document.querySelectorAll('[role=option]')]"

echo "--- unlock"
if [ "$($D eval "!!document.querySelector('#master-password')")" = "true" ]; then
  $D fill "#master-password" "Tactical-Vault-2026" >/dev/null
  $D click "text:browse" >/dev/null; sleep 2; $DLG -Title "Select keyfile" -Path "$KEY" >/dev/null
  waitfor "$body.includes('KEYFILE ATTACHED')"; $D click "button[type=submit]" >/dev/null
fi
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
check "dashboard open" "document.querySelector('nav')"

# Ensure a known existing login: github.com / octo with password "current-pw".
if [ "$($D eval "$opts.some(o => o.textContent.includes('GitHub CSV-test'))")" != "true" ]; then
  $D click "text:New login" >/dev/null; waitfor "document.querySelector('#f-title')"
  $D fill "#f-title" "GitHub CSV-test" >/dev/null; $D fill "#f-username" "octo" >/dev/null
  $D fill "#f-password" "current-pw" >/dev/null; $D fill "#f-url" "https://github.com" >/dev/null
  $D click "button[type=submit]" >/dev/null; waitfor "document.querySelector('article h2')?.textContent === 'GitHub CSV-test'"
fi
BEFORE=$($D eval "$opts.length")

# Chrome-format export: 1 conflict (same host+user, different pw), 2 new, 1 junk row.
printf 'name,url,username,password,note\r\ngithub.com,https://www.github.com/login,OCTO,chrome-pw,\r\nexample.org,https://example.org,alice,ex-pw,"multi\nline note"\r\nmail.test,https://mail.test,bob,mail-pw,\r\n,,,,\r\n' > "$1/e2e/chrome-passwords.csv"

echo "--- preview"
$D click "text:Backup & import" >/dev/null
waitfor "$body.includes('Choose a .csv export')"
$D click "text:Choose a .csv export" >/dev/null; sleep 2
$DLG -Title "Choose a password export (CSV)" -Path "$CSV" >/dev/null
waitfor "document.querySelector('[aria-label=\"CSV preview\"]')" 20000
check "format detected as Chrome" "$body.includes('Detected: Chrome / Edge / Brave')"
check "preview: 3 rows, 2 new, 1 conflict" "(() => { const t = document.querySelector('[aria-label=\"CSV preview\"]').textContent.replace(/\\s+/g,' '); return t.includes('3 rows') && t.includes('2 new') && t.includes('1 conflicts'); })()"
check "junk row reported as skipped" "$body.includes('1 incomplete row will be skipped')"
check "preview did not change the vault" "$opts.length === $BEFORE"
$D shot shots/p6b-01-preview.png >/dev/null

echo "--- import"
$D click "text:IMPORT 2 NEW" >/dev/null
waitfor "$body.includes('Imported 2 items')" 20000
check "2 new logins imported, conflict archived" "$body.includes('Imported 2 items') && $body.includes('1 different password archived')"
check "list grew by 2" "$opts.length === $BEFORE + 2"
check "multi-line note kept" "$opts.some(o => o.textContent.includes('example.org'))"

echo "--- existing password stayed active, CSV one archived"
$D click "text:GitHub CSV-test" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'GitHub CSV-test'"
$D click "[aria-label=\"Reveal password\"]" >/dev/null
waitfor "document.querySelector('[aria-label=\"Hide password\"]')"
check "active password unchanged (current-pw)" "document.querySelector('article').textContent.includes('current-pw')"
check "conflicting CSV password archived in history" "/\\d+ previous passwords? archived/.test(document.querySelector('article').textContent)"

echo "--- re-import is a no-op, then shred"
$D click "text:Backup & import" >/dev/null
waitfor "$body.includes('Choose a .csv export')"
$D click "text:Choose a .csv export" >/dev/null; sleep 2
$DLG -Title "Choose a password export (CSV)" -Path "$CSV" >/dev/null
waitfor "document.querySelector('[aria-label=\"CSV preview\"]')" 20000
check "re-import: nothing new" "$body.includes('NOTHING NEW TO IMPORT')"
# Shred is offered after an import; run the import UI path on a fresh copy.
cp "$1/e2e/chrome-passwords.csv" "$1/e2e/chrome-copy.csv"
printf 'name,url,username,password\r\nnew.site,https://new.site,carol,new-pw\r\n' > "$1/e2e/chrome-copy.csv"
$D click "text:chrome-passwords.csv" >/dev/null; sleep 2
$DLG -Title "Choose a password export (CSV)" -Path "$E2E\\chrome-copy.csv" >/dev/null
waitfor "$body.includes('IMPORT 1 NEW')" 20000
$D click "text:IMPORT 1 NEW" >/dev/null
waitfor "$body.includes('Overwrite & delete the CSV')" 20000
$D click "text:Overwrite & delete the CSV" >/dev/null
waitfor "$body.includes('overwritten and deleted')" 10000
check "UI confirms shredding" "$body.includes('overwritten and deleted')"
[ ! -e "$1/e2e/chrome-copy.csv" ] && { echo "PASS  CSV file is gone from disk"; pass=$((pass+1)); } || { echo "FAIL  CSV still on disk"; fail=$((fail+1)); }
rm -f "$1/e2e/chrome-passwords.csv"

echo "=== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
