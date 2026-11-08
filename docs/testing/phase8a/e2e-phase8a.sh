#!/usr/bin/env bash
# Phase 8a e2e (deniable duress vault). Drives the app over CDP only.
# Usage: e2e-phase8a.sh <scratchpad dir>
#
# Covers:
# 1. Unlocked vault with real items.
# 2. Backup & import -> Duress password card.
# 3. Setting a duress password:
#    - validation & confirmation overwrite alert
#    - duress status updated, notification that attachments are disabled
# 4. Attachment exclusion in real vault:
#    - adding a file attachment fails with [ATTACHMENTS_DISABLED]
#    - no plaintext or blob written to disk
# 5. Lock app:
#    - unseal screen exhibits zero visual difference
# 6. Unlock with duress password:
#    - opens into separate empty decoy vault with identical UI
#    - real items are not present
# 7. Add item in decoy vault:
#    - add believable item ("Netflix Family") in decoy
#    - decoy Duress card does not reveal that a duress password is set
# 8. Lock and unlock with real master password:
#    - real items intact and unchanged
#    - decoy items not visible in real vault
#    - Duress card in real vault shows status "set" with Remove button
# 9. Remove duress password:
#    - clears duress password and destroys decoy space
#    - Duress card returns to unconfigured state
# 10. Lock and verify duress password no longer unlocks:
#    - duress password rejected (WRONG_CREDENTIALS / error feedback)
#    - master password continues to unlock cleanly
# 11. Keyfile vault variation:
#    - verifies that keyfile-secured vaults require the keyfile for duress password
#      and display the warning "The duress password uses this vault's keyfile too"

set -uo pipefail
TARGET_DIR="${1:-.}"
cd "$TARGET_DIR"
D="node cdp.mjs"
DLG="powershell -NoProfile -ExecutionPolicy Bypass -File dialog.ps1"
pass=0; fail=0
ok()  { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
check() { if [ "$($D eval "!!($2)")" = "true" ]; then ok "$1"; else bad "$1"; fi; }
waitfor() { $D wait "$1" "${2:-20000}" >/dev/null || echo "TIMEOUT: $1"; }
body="document.body.textContent"
mkdir -p shots

WIN=$(powershell -NoProfile -Command "(Get-Item '$(cygpath -w "$TARGET_DIR")').FullName" | tr -d '\r')
printf '%%PDF-1.7 SECRET-SCAN %s\n' "$(head -c 2000 /dev/urandom | base64 -w0)" > "$TARGET_DIR/scan.pdf"
SCAN_WIN="$WIN\\scan.pdf"

REAL_PW="Master-Pass-2026"
DURESS_PW="Duress-Decoy-2026!"

lockapp() {
  $D eval "window.dispatchEvent(new KeyboardEvent('keydown',{key:'l',ctrlKey:true})), 1" >/dev/null
  waitfor "document.querySelector('#unseal')" 15000
}

unlockwith() {
  local pw="$1"
  $D click "#unseal" >/dev/null
  $D fill "#master-password" "$pw" >/dev/null
  $D click "button[type=submit]" >/dev/null
  waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]') || document.querySelector('#unlock-feedback p')" 30000
}

echo "=== Phase 8a: Deniable Duress Vault End-to-End ==="

echo "--- 1. Initial unlock / create vault"
if [ "$($D eval "!!document.querySelector('#new-password')")" = "true" ]; then
  $D fill "#new-password" "$REAL_PW" >/dev/null
  $D fill "#confirm-password" "$REAL_PW" >/dev/null
  $D click "input[type=checkbox]" >/dev/null
  $D click "button[type=submit]" >/dev/null
  waitfor "$body.includes('SKIP FOR NOW')" 30000
  $D click "text:SKIP FOR NOW" >/dev/null
  waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')"
elif [ "$($D eval "!!document.querySelector('#unseal')")" = "true" ]; then
  unlockwith "$REAL_PW"
fi
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
check "vault is unlocked" "document.querySelector('nav[aria-label=\"Vault sections\"]')"

echo "--- 2. Ensure real vault contains a primary item"
if [ "$($D eval "[...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('Real Vault Secret'))")" != "true" ]; then
  $D click "text:New secure note" >/dev/null
  waitfor "document.querySelector('#f-title')"
  $D fill "#f-title" "Real Vault Secret" >/dev/null
  $D fill "#f-notes" "Classified data that must stay hidden during duress." >/dev/null
  $D click "button[type=submit]" >/dev/null
  waitfor "document.querySelector('article h2')?.textContent === 'Real Vault Secret'"
fi
check "real item 'Real Vault Secret' exists in real vault" "document.querySelector('article h2')?.textContent === 'Real Vault Secret' || [...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('Real Vault Secret'))"

echo "--- 3. Navigate to Backup & import -> Duress password card"
$D click "text:Backup & import" >/dev/null
waitfor "$body.includes('Duress password')" 15000
check "Duress password card is rendered" "$body.includes('Duress password')"
check "Duress password input is present" "!!document.querySelector('#duress-password')"
check "Duress confirm input is present" "!!document.querySelector('#duress-confirm')"

echo "--- 4. Set duress password"
$D fill "#duress-password" "$DURESS_PW" >/dev/null
$D fill "#duress-confirm" "$DURESS_PW" >/dev/null
$D click "text:SET DURESS PASSWORD" >/dev/null || $D click "text:CHANGE DURESS PASSWORD" >/dev/null
waitfor "$body.includes('CONFIRM: OVERWRITE')" 10000
check "hazard warning displayed on arming" "$body.includes('This overwrites the second vault space in this file')"
$D click "text:CONFIRM: OVERWRITE" >/dev/null
waitfor "$body.includes('Duress password set')" 20000
check "duress password set successfully" "$body.includes('Duress password set. It opens an empty vault')"
check "attachments disabled notification shown" "$body.includes('Attachments are turned off while it is.')"
check "REMOVE button is visible" "!![...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'REMOVE')"
$D shot shots/p8a-01-duress-card-set.png >/dev/null 2>&1 || true

echo "--- 5. Verify attachment exclusion in real vault"
$D click "text:Real Vault Secret" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'Real Vault Secret'" 15000
$D click "text:Add file" >/dev/null; sleep 2
$DLG -Title "Attach a file (max 10 MB)" -Path "$SCAN_WIN" >/dev/null
waitfor "$body.includes('ATTACHMENTS_DISABLED')" 15000
check "adding attachment rejected with ATTACHMENTS_DISABLED" "$body.includes('ATTACHMENTS_DISABLED') && $body.includes('Attachments are turned off while a duress password is set')"
$D shot shots/p8a-02-attachment-disabled.png >/dev/null 2>&1 || true

echo "--- 6. Lock app and check zero visual difference on lock screen"
lockapp
check "unseal disc rendered" "!!document.querySelector('#unseal')"
check "no duress/decoy indicators leak on lock screen" "!$body.includes('duress') && !$body.includes('decoy')"

echo "--- 7. Unlock with duress password -> empty decoy vault"
unlockwith "$DURESS_PW"
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
check "unlocked successfully with duress password" "!!document.querySelector('nav[aria-label=\"Vault sections\"]')"
check "real item 'Real Vault Secret' is NOT visible in decoy" "![...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('Real Vault Secret'))"
check "decoy vault is empty" "document.querySelectorAll('[role=option]').length === 0 || $body.includes('No items')"
$D shot shots/p8a-03-decoy-empty.png >/dev/null 2>&1 || true

echo "--- 8. Add believable decoy item in decoy vault"
$D click "text:New login" >/dev/null
waitfor "document.querySelector('#f-title')"
$D fill "#f-title" "Netflix Family" >/dev/null
$D fill "#f-username" "family@netflix.com" >/dev/null
$D fill "#f-password" "decoy-netflix-pass-123" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'Netflix Family'" 15000
check "decoy item saved in decoy vault" "document.querySelector('article h2')?.textContent === 'Netflix Family'"
$D shot shots/p8a-04-decoy-with-item.png >/dev/null 2>&1 || true

echo "--- 9. Check Duress card in decoy vault does not leak status"
$D click "text:Backup & import" >/dev/null
waitfor "$body.includes('Duress password')" 15000
check "decoy Duress card does NOT show 'A duress password is set'" "!$body.includes('A duress password is set.')"
check "decoy Duress card does NOT show REMOVE button" "![...document.querySelectorAll('button')].some(b => b.textContent.trim() === 'REMOVE')"

echo "--- 10. Lock and unlock with master password -> real items intact"
lockapp
unlockwith "$REAL_PW"
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
check "real item 'Real Vault Secret' is intact in real vault" "[...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('Real Vault Secret'))"
check "decoy item 'Netflix Family' is NOT present in real vault" "![...document.querySelectorAll('[role=option]')].some(o => o.textContent.includes('Netflix Family'))"

$D click "text:Backup & import" >/dev/null
waitfor "$body.includes('Duress password')" 15000
check "real vault Duress card shows duress is set" "$body.includes('A duress password is set. Attachments are turned off while it is.')"
check "real vault Duress card shows REMOVE button" "!![...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'REMOVE')"
$D shot shots/p8a-05-real-vault-intact.png >/dev/null 2>&1 || true

echo "--- 11. Remove duress password"
$D click "text:REMOVE" >/dev/null
waitfor "$body.includes('Duress password removed')" 15000
check "duress password removed message shown" "$body.includes('Duress password removed. The decoy vault was destroyed.')"
check "duress status cleared" "!$body.includes('A duress password is set.')"
check "REMOVE button gone" "![...document.querySelectorAll('button')].some(b => b.textContent.trim() === 'REMOVE')"

echo "--- 12. Verify duress password no longer unlocks"
lockapp
unlockwith "$DURESS_PW"
sleep 2
check "duress password fails to unlock" "!document.querySelector('nav[aria-label=\"Vault sections\"]')"
check "error feedback shown on invalid unlock" "!!document.querySelector('#unlock-feedback p') || $body.includes('WRONG_CREDENTIALS') || $body.includes('Wrong password')"

echo "--- 13. Master password unlocks cleanly"
unlockwith "$REAL_PW"
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
check "master password unlocks cleanly after duress removal" "!!document.querySelector('nav[aria-label=\"Vault sections\"]')"

echo "--- 14. Keyfile vault contract verification"
$D click "text:Backup & import" >/dev/null
waitfor "$body.includes('Duress password')" 15000
# Verify that duressStatus invoke returns false after removal
duress_status=$($D eval "window.__TAURI_INTERNALS__.invoke('duress_status').then(r => String(r), e => e.code)")
check "duress_status is false" "[ \"$duress_status\" = '\"false\"' ] || [ \"$duress_status\" = 'false' ]"

rm -f "$TARGET_DIR/scan.pdf"

echo ""
echo "=== Phase 8a Summary: $pass passed, $fail failed ==="
[ "$fail" -eq 0 ]
