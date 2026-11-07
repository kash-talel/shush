#!/usr/bin/env bash
# Phase 4c e2e (attachments). Usage: e2e-phase4c.sh <scratchpad dir>   (vault: e2e7, password only)
set -uo pipefail
cd "$1"
D="node cdp.mjs"; DLG="powershell -NoProfile -ExecutionPolicy Bypass -File dialog.ps1"
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
check() { if [ "$($D eval "!!($2)")" = "true" ]; then ok "$1"; else bad "$1"; fi; }
waitfor() { $D wait "$1" "${2:-15000}" >/dev/null || echo "TIMEOUT: $1"; }
body="document.body.textContent"
V="$1/e2e7"; WV=$(powershell -NoProfile -Command "(Get-Item '$(cygpath -w "$V")').FullName" | tr -d '\r')
rm -rf "$V/out" "$V"/*.shushbackup; mkdir -p "$V/out"
printf '%%PDF-1.7 SECRET-STATEMENT %s\n' "$(head -c 3000 /dev/urandom | base64 -w0)" > "$V/scan.pdf"

echo "--- unlock, create an item to attach to"
if [ "$($D eval "!!document.querySelector('#master-password')")" = "true" ]; then
  $D fill "#master-password" "Onboarding-Test-2026" >/dev/null; $D click "button[type=submit]" >/dev/null
fi
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
$D click "text:New secure note" >/dev/null; waitfor "document.querySelector('#f-title')"
$D fill "#f-title" "Bank documents" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'Bank documents'"
check "item open with empty attachments" "$body.includes('No files. Attach')"

echo "--- attach a file"
$D click "text:Add file" >/dev/null; sleep 2
$DLG -Title "Attach a file (max 10 MB)" -Path "$WV\\scan.pdf" >/dev/null
waitfor "document.querySelector('[aria-label=Attachments] li')" 20000
check "attachment listed with name and size" "document.querySelector('[aria-label=Attachments] li')?.textContent.includes('scan.pdf')"
blob=$(ls "$V/vault.shush.d/"*.blob 2>/dev/null | head -1)
[ -n "$blob" ] && [ "$(head -c 5 "$blob")" = "SHATT" ] && ok "sealed blob written beside the vault" || bad "blob file"
grep -q "SECRET-STATEMENT" "$blob" 2>/dev/null && bad "plaintext leaked into blob" || ok "no plaintext in blob"
grep -q "SECRET-STATEMENT" "$V/vault.shush" && bad "plaintext in vault file" || ok "no plaintext in vault file"
$D shot shots/p4c-01-attachment.png >/dev/null

echo "--- save it back out"
$D click "[aria-label=\"Save scan.pdf\"]" >/dev/null; sleep 2
$DLG -Title "Save attachment" -Path "$WV\\out\\scan-copy.pdf" >/dev/null
waitfor "$body.includes('Saved scan.pdf')"
cmp -s "$V/scan.pdf" "$V/out/scan-copy.pdf" && ok "saved copy is byte-identical" || bad "saved copy differs"

echo "--- backup embeds it; clean restore brings it back"
$D click "text:Backup & import" >/dev/null; waitfor "$body.includes('EXPORT BACKUP')"
$D click "text:EXPORT BACKUP" >/dev/null; sleep 2
$DLG -Title "Save encrypted backup" -Path "$WV\\with-files.shushbackup" >/dev/null
waitfor "$body.includes('saved to with-files.shushbackup')" 30000
check "backup exported" "$body.includes('saved to with-files.shushbackup')"
$D click "text:Bank documents" >/dev/null; waitfor "document.querySelector('[aria-label=Attachments] li')"
$D click "[aria-label=\"Delete scan.pdf\"]" >/dev/null; $D click "[aria-label=\"Click again to delete scan.pdf\"]" >/dev/null
waitfor "$body.includes('No files. Attach')"
[ -z "$(ls "$V/vault.shush.d/"*.blob 2>/dev/null)" ] && ok "deleting the attachment removed its blob" || bad "blob left after delete"
$D click "text:Backup & import" >/dev/null; waitfor "$body.includes('Choose a .shushbackup file')"
$D click "text:Choose a .shushbackup file" >/dev/null; sleep 2
$DLG -Title "Choose a backup to import" -Path "$WV\\with-files.shushbackup" >/dev/null
waitfor "document.querySelector('#import-password')"
$D fill "#import-password" "Onboarding-Test-2026" >/dev/null
$D click "text:DECRYPT" >/dev/null; waitfor "document.querySelector('[aria-label=\"Import preview\"]')" 30000
$D click "input[value=replace]" >/dev/null
$D click "text:RESTORE BACKUP" >/dev/null; $D click "text:CONFIRM: REPLACE VAULT CONTENTS" >/dev/null
waitfor "$body.includes('Vault restored from backup')" 30000
$D click "text:Bank documents" >/dev/null
waitfor "document.querySelector('[aria-label=Attachments] li')" 15000
check "attachment restored from backup" "document.querySelector('[aria-label=Attachments] li')?.textContent.includes('scan.pdf')"
$D click "[aria-label=\"Save scan.pdf\"]" >/dev/null; sleep 2
$DLG -Title "Save attachment" -Path "$WV\\out\\restored.pdf" >/dev/null
waitfor "$body.includes('Saved scan.pdf')"
cmp -s "$V/scan.pdf" "$V/out/restored.pdf" && ok "restored file is byte-identical" || bad "restored file differs"

echo "--- deleting the item cleans up its blob"
$D click "text:Delete" >/dev/null; $D click "text:Click again to delete" >/dev/null
waitfor "![...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('Bank documents'))"
[ -z "$(ls "$V/vault.shush.d/"*.blob 2>/dev/null)" ] && ok "item delete removed its attachment blob" || bad "orphan blob after item delete"

rm -rf "$V/out" "$V/scan.pdf"
echo "=== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
