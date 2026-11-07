#!/usr/bin/env bash
# Phase 4 end-to-end over CDP. Usage: e2e-phase4.sh <scratchpad dir>
set -uo pipefail
cd "$1"
D="node cdp.mjs"
pass=0; fail=0
check() { # check "<description>" "<js predicate>"
  if [ "$($D eval "!!($2)")" = "true" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi
}
waitfor() { $D wait "$1" "${2:-15000}" >/dev/null || echo "TIMEOUT waiting for: $1"; }
KEY=$(powershell -NoProfile -Command "(Get-Item '$(cygpath -w "$1/e2e/usb/vault.key")').FullName")

echo "--- unlock"
$D fill "#master-password" "Tactical-Vault-2026" >/dev/null
$D click "text:browse" >/dev/null; sleep 2
powershell -NoProfile -ExecutionPolicy Bypass -File dialog.ps1 -Title "Select keyfile" -Path "$KEY" >/dev/null
waitfor "document.body.textContent.includes('KEYFILE ATTACHED')"
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
check "dashboard shown after unlock" "document.querySelector('nav[aria-label=\"Vault sections\"]')"

echo "--- create login with generated password + TOTP"
$D click "text:New login" >/dev/null
waitfor "document.querySelector('#f-title')"
$D fill "#f-title" "GitHub" >/dev/null
$D fill "#f-username" "octocat@example.com" >/dev/null
$D click "text:Generate password" >/dev/null
waitfor "document.querySelector('output')?.textContent.trim().length >= 20"
$D click "text:USE THIS PASSWORD" >/dev/null
$D fill "#f-url" "https://github.com/login" >/dev/null
$D click "#f-totp" >/dev/null
waitfor "document.querySelector('input#f-totp')"
$D fill "#f-totp" "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ" >/dev/null
$D fill "#f-tags" "dev, work" >/dev/null
GEN=$($D eval "document.querySelector('#f-password').value")
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'GitHub'"
check "detail shows new login" "document.querySelector('article h2')?.textContent === 'GitHub'"
waitfor "/\\d{3} \\d{3}/.test(document.querySelector('[aria-label=\"Copy one-time code\"]')?.textContent ?? '')"
check "live TOTP code rendered" "/\\d{3} \\d{3}/.test(document.querySelector('[aria-label=\"Copy one-time code\"]')?.textContent ?? '')"
check "password concealed by default" "document.body.textContent.includes('••••••••••••')"
check "tags rendered" "document.body.textContent.includes('#dev') && document.body.textContent.includes('#work')"
$D shot shots/p4-01-login.png >/dev/null

echo "--- reveal password matches generated one"
$D click "[aria-label=\"Reveal password\"]" >/dev/null
waitfor "document.querySelector('[aria-label=\"Hide password\"]')"
check "revealed password equals generated" "document.querySelector('article').textContent.includes($GEN)"
$D click "[aria-label=\"Hide password\"]" >/dev/null

echo "--- edit without touching password keeps it (no history)"
$D click "text:Edit" >/dev/null
waitfor "document.querySelector('#f-title')"
check "editor does not load the password" "!document.querySelector('#f-password') && document.body.textContent.includes('unchanged')"
$D fill "#f-title" "GitHub (work)" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'GitHub (work)'"
check "title updated, no history" "!document.body.textContent.includes('previous password')"

echo "--- edit with new password archives the old one"
$D click "text:Edit" >/dev/null
waitfor "document.querySelector('#f-title')"
$D click "text:unchanged" >/dev/null
waitfor "document.querySelector('#f-password')"
$D fill "#f-password" "brand-new-Passw0rd!" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.body.textContent.includes('1 previous password archived')"
check "old password archived" "document.body.textContent.includes('1 previous password archived')"

echo "--- secure note: XSS probe stays text"
$D click "text:New secure note" >/dev/null
waitfor "document.querySelector('#f-content')"
$D fill "#f-title" "Recovery codes" >/dev/null
$D eval "(() => { const t = document.querySelector('#f-content'); const set = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set; set.call(t, '<img src=x onerror=\"window.__xss=1\"> codes: 1111-2222'); t.dispatchEvent(new Event('input',{bubbles:true})); return 1; })()" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'Recovery codes'"
sleep 1
check "note markup not executed or rendered" "!window.__xss && !document.querySelector('article img') && document.querySelector('article').textContent.includes('<img src=x')"
$D shot shots/p4-02-note.png >/dev/null

echo "--- search, favorite, filters"
$D fill "input[type=search]" "octo" >/dev/null
check "search filters to the login" "document.querySelectorAll('[role=option]').length === 1 && document.querySelector('[role=option]').textContent.includes('GitHub')"
$D fill "input[type=search]" "" >/dev/null
$D click "text:Recovery codes" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'Recovery codes'"
$D click "[aria-label=\"Add to favorites\"]" >/dev/null
waitfor "document.querySelector('[aria-label=\"Remove from favorites\"]')"
$D click "text:Favorites" >/dev/null
check "favorites filter shows only the note" "document.querySelectorAll('[role=option]').length === 1 && document.querySelector('[role=option]').textContent.includes('Recovery')"
$D click "text:All items" >/dev/null

echo "--- two-step delete"
$D click "text:Delete" >/dev/null
check "first click only arms delete" "document.body.textContent.includes('Click again to delete') && document.querySelectorAll('[role=option]').length === 2"
$D click "text:Click again to delete" >/dev/null
waitfor "document.querySelectorAll('[role=option]').length === 1"
check "note deleted" "document.querySelectorAll('[role=option]').length === 1"

echo "--- lock and unlock again: data persisted"
$D eval "window.dispatchEvent(new KeyboardEvent('keydown',{key:'l',ctrlKey:true})), 1" >/dev/null
waitfor "document.querySelector('#master-password')"
check "locked" "document.querySelector('footer').textContent.includes('LOCKED')"
$D fill "#master-password" "Tactical-Vault-2026" >/dev/null
$D click "text:browse" >/dev/null; sleep 2
powershell -NoProfile -ExecutionPolicy Bypass -File dialog.ps1 -Title "Select keyfile" -Path "$KEY" >/dev/null
waitfor "document.body.textContent.includes('KEYFILE ATTACHED')"
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelectorAll('[role=option]').length === 1" 30000
check "login persisted across lock/unlock" "document.querySelector('[role=option]')?.textContent.includes('GitHub (work)')"
$D shot shots/p4-03-after-relock.png >/dev/null

echo "=== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
