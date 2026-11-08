#!/usr/bin/env bash
# Multiple vaults: create elsewhere, switch, colours, edit, open existing,
# remove from list, and the guarded delete. Drives the app over CDP only.
# Usage: e2e-multi-vault.sh <folder with cdp.mjs from phase5b + dialog.ps1 from phase5>
# Expects a fresh scratch vault: SHUSH_VAULT_PATH=<folder>/e2e/vault.shush, nothing created yet.
set -uo pipefail
cd "$1"
D="node cdp.mjs"; DLG="powershell -NoProfile -ExecutionPolicy Bypass -File dialog.ps1"
pass=0; fail=0
ok() { echo "PASS  $1"; pass=$((pass+1)); }
bad() { echo "FAIL  $1"; fail=$((fail+1)); }
check() { if [ "$($D eval "!!($2)")" = "true" ]; then ok "$1"; else bad "$1"; fi; }
waitfor() { $D wait "$1" "${2:-20000}" >/dev/null || echo "TIMEOUT waiting for: $1"; }
body="document.body.textContent"
WIN=$(powershell -NoProfile -Command "(Get-Item '$(cygpath -w "$1")').FullName" | tr -d '\r')
A="Personal-Pass-2026"; B="Work-Pass-2026!"
disc="(document.querySelector('#unseal .disc')?.getAttribute('src') ?? '')"
slots="[...document.querySelectorAll('[aria-label=Vaults] [role=radio]')]"
invoke() { $D eval "window.__TAURI_INTERNALS__.invoke($1).then(() => 'OK', e => e.code)" | tr -d '"'; }
lockapp() { $D eval "window.dispatchEvent(new KeyboardEvent('keydown',{key:'l',ctrlKey:true})), 1" >/dev/null; waitfor "document.querySelector('#unseal')"; }
create() { # password
  $D fill "#new-password" "$1" >/dev/null; $D fill "#confirm-password" "$1" >/dev/null
  $D click "input[type=checkbox]" >/dev/null; $D click "button[type=submit]" >/dev/null
  waitfor "$body.includes('SKIP FOR NOW')" 30000; $D click "text:SKIP FOR NOW" >/dev/null
  waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')"
}
unlockwith() { # password -> waits for dashboard or error
  $D click "#unseal" >/dev/null; $D fill "#master-password" "$1" >/dev/null
  $D click "button[type=submit]" >/dev/null
  waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]') || document.querySelector('#unlock-feedback p')" 30000
}

$D eval "location.reload()" >/dev/null; sleep 2.5
echo "--- first run is unchanged"
waitfor "document.querySelector('#new-password')"
check "first run shows the create screen" "$body.includes('No vault found here yet')"
check "no back button on first run" "!$body.includes('Back to vaults')"
create "$A"
lockapp
check "single vault: name shown, no rack" "$body.includes('Personal') && $slots.length === 0"
check "single vault: New vault action offered" "$body.includes('New vault')"
check "default vault has the crimson disc" "$disc.endsWith('/disc.png')"
grep -q '"Personal"' e2e/vaults.json && ok "vaults.json lists the default vault" || bad "vaults.json missing default"

echo "--- new vault at a chosen location"
$D click "text:New vault" >/dev/null; waitfor "document.querySelector('dialog[open]')"
$D fill "dialog input[maxlength]" "personal" >/dev/null
check "duplicate name is flagged" "$body.includes('Another vault already has this name.')"
$D fill "dialog input[maxlength]" "Work" >/dev/null
$D click "[aria-label=Teal]" >/dev/null
$D click "text:Choose a folder and file name" >/dev/null; sleep 2
$DLG -Title "Where to save the new vault" -Path "$WIN\\usb\\work" >/dev/null
waitfor "$body.includes('work.shush')"
$D shot shots/01-new-vault-dialog.png >/dev/null
$D click "text:SET PASSWORD" >/dev/null
waitfor "$body.includes('New vault: Work')"
check "create screen names the new vault" "$body.includes('New vault: Work') && $body.includes('Back to vaults')"
check "create screen shows the teal disc" "[...document.querySelectorAll('.disc')].some(d => d.getAttribute('src').includes('disc-teal'))"
create "$B"
[ -f usb/work.shush ] && ok "work.shush written at the chosen location" || bad "no usb/work.shush"
lockapp
check "rack shows both vaults" "$slots.length === 2"
check "the new vault is selected, teal" "$disc.includes('disc-teal') && $body.includes('Work')"
$D shot shots/02-rack.png >/dev/null

echo "--- switching"
$D click "text:Personal" >/dev/null
waitfor "$disc.endsWith('/disc.png')"
check "switch swaps the big case to crimson, still sealed" "$disc.endsWith('/disc.png') && document.querySelector('#unseal').getAttribute('aria-expanded') === 'false'"
unlockwith "$B"
check "the other vault's password does not open it" "!!document.querySelector('#unlock-feedback p') && $body.includes('WRONG_CREDENTIALS')"
$D fill "#master-password" "$A" >/dev/null; $D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
check "Personal opens with its own password" "!!document.querySelector('nav[aria-label=\"Vault sections\"]')"
r=$(invoke "'forget_vault', {id: 'x'}"); [ "$r" = "VAULT_UNLOCKED" ] && ok "list changes refused while a vault is open" || bad "got $r"
lockapp
check "lock returns to the last used vault" "$disc.endsWith('/disc.png')"

echo "--- edit"
$D click "text:Work" >/dev/null; waitfor "$disc.includes('disc-teal')"
$D click "text:Edit" >/dev/null; waitfor "document.querySelector('dialog[open]')"
$D fill "dialog input[maxlength]" "Work USB" >/dev/null
$D click "[aria-label=Violet]" >/dev/null
$D click "text:SAVE" >/dev/null
waitfor "$body.includes('Work USB')"
check "rename and recolour apply" "$body.includes('Work USB') && $disc.includes('disc-violet')"

echo "--- open an existing vault file"
cp usb/work.shush usb/copy.shush
$D click "text:Open vault file" >/dev/null; waitfor "document.querySelector('dialog[open]')"
$D click "text:Choose a .shush file" >/dev/null; sleep 2
$DLG -Title "Open a shush vault" -Path "$WIN\\usb\\copy.shush" >/dev/null
waitfor "document.querySelector('dialog input[maxlength]')?.value === 'copy'"
check "name defaults to the file name" "document.querySelector('dialog input[maxlength]').value === 'copy'"
$D click "text:ADD VAULT" >/dev/null
waitfor "$slots.length === 3"
check "added vault appears and is selected" "$slots.length === 3 && document.querySelector('#unseal').getAttribute('aria-label').includes('copy')"
r=$(invoke "'add_existing_vault', {path: '$(cygpath -w "$1/usb/work.shush" | sed 's/\\/\\\\/g')', name: 'dup', color: null}")
[ "$r" = "VAULT_ALREADY_LISTED" ] && ok "same file cannot be listed twice" || bad "got $r"
echo "not a vault" > usb/fake.shush
r=$(invoke "'add_existing_vault', {path: '$(cygpath -w "$1/usb/fake.shush" | sed 's/\\/\\\\/g')', name: 'fake', color: null}")
[ "$r" = "VAULT_UNREADABLE" ] && ok "a non-vault file is refused" || bad "got $r"

echo "--- remove from list keeps the file"
$D click "text:Edit" >/dev/null; waitfor "document.querySelector('dialog[open]')"
$D click "text:Remove from list" >/dev/null
check "removal asks for a second click" "$body.includes('Click again to remove')"
$D click "text:Click again to remove" >/dev/null
waitfor "$slots.length === 2"
[ -f usb/copy.shush ] && ok "file kept after removing from list" || bad "copy.shush gone"
pid=$($D eval "window.__TAURI_INTERNALS__.invoke('list_vaults').then(l => l.vaults.find(v => v.is_default).id)" | tr -d '"')
r=$(invoke "'forget_vault', {id: '$pid'}"); [ "$r" = "DEFAULT_VAULT_PINNED" ] && ok "default vault cannot be removed from list" || bad "got $r"

echo "--- guarded delete"
$D click "text:Work USB" >/dev/null; waitfor "$disc.includes('disc-violet')"
$D click "text:Delete" >/dev/null; waitfor "document.querySelector('dialog[open]')"
$D fill "dialog input[autocomplete=off]" "work usb" >/dev/null
$D fill "#delete-password" "$B" >/dev/null
check "wrong-case name keeps Delete disabled" "document.querySelector('dialog button[type=submit]').disabled"
$D fill "dialog input[autocomplete=off]" "Work USB" >/dev/null
for i in 1 2 3; do
  # Typing clears the error; wait for the reply to this attempt.
  $D fill "#delete-password" "wrong-$i" >/dev/null; $D click "dialog button[type=submit]" >/dev/null
  waitfor "document.querySelector('dialog [aria-live] p')" 30000
done
check "third wrong password starts a wait" "$body.includes('Try again in 30 seconds')"
$D shot shots/03-delete-throttled.png >/dev/null
$D fill "#delete-password" "$B" >/dev/null; $D click "dialog button[type=submit]" >/dev/null
waitfor "document.querySelector('dialog [aria-live] p')" 30000
check "even the right password waits out the cooldown" "$body.includes('DELETE_COOLDOWN')"
[ -f usb/work.shush ] && ok "vault untouched by failed attempts" || bad "vault gone early"
echo "      waiting out the 30 s cooldown"; sleep 31
$D fill "#delete-password" "$B" >/dev/null; $D click "dialog button[type=submit]" >/dev/null
waitfor "!document.querySelector('dialog[open]')" 30000
check "dialog closes after deleting" "!document.querySelector('dialog[open]')"
[ ! -e usb/work.shush ] && [ ! -e usb/work.shush.bak ] && [ ! -e usb/work.shush.d ] && ok "vault files moved off disk (Recycle Bin)" || bad "files remain"
check "rack gone, back to the default vault" "$slots.length === 0 && $disc.endsWith('/disc.png')"
grep -q 'Work USB' e2e/vaults.json && bad "deleted vault still listed" || ok "deleted vault removed from vaults.json"
unlockwith "$A"
check "remaining vault still opens" "!!document.querySelector('nav[aria-label=\"Vault sections\"]')"
lockapp

echo "=== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
