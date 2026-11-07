#!/usr/bin/env bash
# Phase 6 e2e (backup export / import) over CDP. Usage: e2e-phase6.sh <scratchpad dir>
set -uo pipefail
cd "$1"
D="node cdp.mjs"; DLG="powershell -NoProfile -ExecutionPolicy Bypass -File dialog.ps1"
pass=0; fail=0
check() { if [ "$($D eval "!!($2)")" = "true" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
waitfor() { $D wait "$1" "${2:-15000}" >/dev/null || echo "TIMEOUT waiting for: $1"; }
win() { powershell -NoProfile -Command "(New-Item -ItemType Directory -Force '$(cygpath -w "$1/e2e")').FullName" | tr -d '\r'; }
E2E=$(win "$1"); KEY="$E2E\\usb\\vault.key"; B1="$E2E\\backup-same.shushbackup"; B2="$E2E\\backup-dedicated.shushbackup"
rm -f "$1"/e2e/*.shushbackup*
body() { echo "document.body.textContent"; }

echo "--- unlock"
if [ "$($D eval "!!document.querySelector('#master-password')")" = "true" ]; then
  $D fill "#master-password" "Tactical-Vault-2026" >/dev/null
  $D click "text:browse" >/dev/null; sleep 2; $DLG -Title "Select keyfile" -Path "$KEY" >/dev/null
  waitfor "$(body).includes('KEYFILE ATTACHED')"
  $D click "button[type=submit]" >/dev/null
fi
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
check "dashboard open" "document.querySelector('nav[aria-label=\"Vault sections\"]')"
if [ "$($D eval "[...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('GitHub (work)'))")" != "true" ]; then
  $D click "text:New login" >/dev/null; waitfor "document.querySelector('#f-title')"
  $D fill "#f-title" "GitHub (work)" >/dev/null; $D click "text:Generate password" >/dev/null
  waitfor "document.querySelector('output')?.textContent.trim().length >= 20"; $D click "text:USE THIS PASSWORD" >/dev/null
  $D click "button[type=submit]" >/dev/null; waitfor "document.querySelector('article h2')?.textContent === 'GitHub (work)'"
fi
check "login present before backup" "[...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('GitHub (work)'))"

echo "--- export with the vault's credentials"
$D click "text:Backup & restore" >/dev/null
waitfor "$(body).includes('BACKUP_AND_RESTORE')"
$D click "text:EXPORT BACKUP" >/dev/null; sleep 2
$DLG -Title "Save encrypted backup" -Path "$B1" >/dev/null
waitfor "$(body).includes('saved to backup-same.shushbackup')" 20000
check "export reports success" "$(body).includes('saved to backup-same.shushbackup')"
magic=$(head -c 5 "$1/e2e/backup-same.shushbackup" 2>/dev/null)
[ "$magic" = "SHBKP" ] && { echo "PASS  file starts with SHBKP magic"; pass=$((pass+1)); } || { echo "FAIL  magic ($magic)"; fail=$((fail+1)); }
grep -q "GitHub" "$1/e2e/backup-same.shushbackup" && { echo "FAIL  plaintext in backup"; fail=$((fail+1)); } || { echo "PASS  no plaintext titles in backup file"; pass=$((pass+1)); }

echo "--- export with a separate password"
$D click "text:Separate password" >/dev/null
waitfor "document.querySelector('#backup-password')"
$D fill "#backup-password" "Backup-Pass-99" >/dev/null
$D click "text:EXPORT BACKUP" >/dev/null; sleep 2
$DLG -Title "Save encrypted backup" -Path "$B2" >/dev/null
waitfor "$(body).includes('saved to backup-dedicated.shushbackup')" 30000
check "dedicated-password export succeeds" "$(body).includes('saved to backup-dedicated.shushbackup')"

echo "--- delete the login, then merge it back from the backup"
$D click "text:GitHub (work)" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'GitHub (work)'"
$D click "text:Delete" >/dev/null; $D click "text:Click again to delete" >/dev/null
waitfor "![...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('GitHub (work)'))"
check "login deleted" "![...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('GitHub (work)'))"

$D click "text:Backup & restore" >/dev/null
waitfor "$(body).includes('Choose a .shushbackup file')"
$D click "text:Choose a .shushbackup file" >/dev/null; sleep 2
$DLG -Title "Choose a backup to import" -Path "$B2" >/dev/null
waitfor "document.querySelector('#import-password')"
$D fill "#import-password" "wrong-password" >/dev/null
$D click "text:DECRYPT" >/dev/null
waitfor "$(body).includes('WRONG_CREDENTIALS')" 30000
check "wrong backup password rejected" "$(body).includes('WRONG_CREDENTIALS')"
$D fill "#import-password" "Backup-Pass-99" >/dev/null
$D click "text:DECRYPT" >/dev/null
waitfor "document.querySelector('[aria-label=\"Import preview\"]')" 30000
check "preview: 1 new item" "document.querySelector('[aria-label=\"Import preview\"]')?.textContent.replace(/\\s+/g,' ').includes('1 new')"
$D shot shots/p6-01-preview.png >/dev/null
$D click "text:MERGE INTO VAULT" >/dev/null
waitfor "$(body).includes('1 new item added')" 20000
check "merge restored the deleted login" "[...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('GitHub (work)'))"

echo "--- clean restore needs a second confirmation"
$D fill "#import-password" "Backup-Pass-99" >/dev/null
$D click "text:DECRYPT" >/dev/null
waitfor "document.querySelector('[aria-label=\"Import preview\"]')" 30000
check "re-import preview shows nothing new" "document.querySelector('[aria-label=\"Import preview\"]')?.textContent.replace(/\\s+/g,' ').includes('0 new')"
$D click "input[value=replace]" >/dev/null
$D click "text:RESTORE BACKUP" >/dev/null
check "first click only asks for confirmation" "$(body).includes('CONFIRM: REPLACE VAULT CONTENTS')"
BAK_BEFORE=$(stat -c %Y "$1/e2e/vault.shush.bak" 2>/dev/null || echo 0); sleep 1
$D click "text:CONFIRM: REPLACE VAULT CONTENTS" >/dev/null
waitfor "$(body).includes('Vault restored from backup')" 20000
check "restore completed and mentions the .bak" "$(body).includes('vault.shush.bak')"
[ "$(stat -c %Y "$1/e2e/vault.shush.bak" 2>/dev/null || echo 0)" -gt "$BAK_BEFORE" ] && { echo "PASS  restore wrote a fresh vault.shush.bak"; pass=$((pass+1)); } || { echo "FAIL  no .bak"; fail=$((fail+1)); }

echo "=== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
