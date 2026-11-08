#!/usr/bin/env bash
# Verifies the "Unseal the Vault" unlock ritual over CDP (no OS input).
# Usage: [MODE=full] e2e-unlock-ritual.sh <folder with cdp.mjs + win.ps1 from phase5>; vault password Onboarding-Test-2026.
# MODE=reduce (default) checks prefers-reduced-motion behaviour; for MODE=full run `node motion.mjs 150 &` first.
set -uo pipefail
cd "$1"; MODE=${MODE:-reduce}; OUT=ritual-$MODE; mkdir -p $OUT
IDLE=$([ "$MODE" = full ] && echo 1 || echo 0)  # disc rate expected when unsealed and idle
D="node cdp.mjs"
pass=0; fail=0
check() { if [ "$($D eval "!!($2)")" = "true" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
waitfor() { $D wait "$1" "${2:-20000}" >/dev/null || echo "TIMEOUT waiting for: $1"; }
lid="getComputedStyle(document.querySelector('#unseal .lid')).transform"
rate="(document.querySelector('#unseal .disc').getAnimations()[0]?.playbackRate ?? -1)"
form="document.querySelector('#unlock-form')"

$D eval "location.reload()" >/dev/null; sleep 2.5
waitfor "document.readyState === 'complete' && document.querySelector('#unseal')?.getAttribute('aria-expanded') === 'false'"; sleep 1
echo "--- sealed"
check "case is focused on launch" "document.activeElement?.id === 'unseal'"
check "lid fully closed" "$lid === 'none' || $lid === 'matrix(1, 0, 0, 1, 0, 0)'"
check "disc stationary" "$rate === 0"
check "prompt shown" "document.body.textContent.includes('[ CLICK DISC TO UNSEAL VAULT ]')"
check "credentials hidden and inert" "$form.inert && getComputedStyle($form).opacity === '0'"
check "case announces it unseals" "document.querySelector('#unseal').getAttribute('aria-expanded') === 'false'"
$D shot $OUT/01-sealed.png >/dev/null

echo "--- unseal"
$D click "#unseal" >/dev/null; sleep 0.35
$D shot $OUT/02-swinging.png >/dev/null
sleep 1.4
check "lid swung open (about -65deg)" "(() => { const m = new DOMMatrix($lid); const deg = Math.atan2(-m.m13, m.m11) * 180 / Math.PI; return Math.abs(deg + 65) < 2; })()"
check "disc idles (rate $IDLE)" "Math.abs($rate - $IDLE) < 0.02"
check "form revealed" "!$form.inert && getComputedStyle($form).opacity === '1'"
check "password input focused" "document.activeElement?.id === 'master-password'"
$D shot $OUT/03-unsealed.png >/dev/null

echo "--- reseal via button"
check "back button visible and enabled" "!!document.querySelector('button[aria-label=\"Choose another vault\"]:not(:disabled)')"
$D click "button[aria-label=\"Choose another vault\"]" >/dev/null; sleep 1
check "resealed via button: lid closed" "$lid === 'none' || $lid === 'matrix(1, 0, 0, 1, 0, 0)'"
check "resealed via button: disc still, form inert" "$rate === 0 && $form.inert"
check "disc button focused after reseal" "document.activeElement?.id === 'unseal'"

echo "--- unseal and reseal via Esc"
$D click "#unseal" >/dev/null; sleep 1.4
$D fill "#master-password" "some-typed-password" >/dev/null
$D eval "window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))" >/dev/null; sleep 1
check "resealed via Esc: lid closed" "$lid === 'none' || $lid === 'matrix(1, 0, 0, 1, 0, 0)'"
check "resealed via Esc: disc still, form inert" "$rate === 0 && $form.inert"
check "password was cleared on reseal" "document.querySelector('#master-password').value === ''"
check "disc button focused after Esc reseal" "document.activeElement?.id === 'unseal'"

# Re-open for the remainder of the test
$D click "#unseal" >/dev/null; sleep 1.4

echo "--- wrong password"
$D fill "#master-password" "wrong-password" >/dev/null
# Record every frame in the page: CDP round trips are too slow to sample a spike.
$D eval "(() => { window.__rec = { maxRate: 0, shudder: false, flash: 0 }; const tick = () => { const a = document.querySelector('#unseal .disc')?.getAnimations()[0]; if (a) __rec.maxRate = Math.max(__rec.maxRate, a.playbackRate); const c = document.querySelector('#unseal'); if (c?.classList.contains('shudder')) { __rec.shudder = true; __rec.flash = Math.max(__rec.flash, +getComputedStyle(c.querySelector('.flash')).opacity); } requestAnimationFrame(tick); }; tick(); return 1; })()" >/dev/null
$D click "button[type=submit]" >/dev/null; sleep 0.25
$D shot $OUT/04-deriving.png >/dev/null
waitfor "document.body.textContent.includes('WRONG_CREDENTIALS')" 30000
$D shot $OUT/05-shudder.png >/dev/null
sleep 1
check "disc spun up while deriving (peak > 8x)" "__rec.maxRate > 8"
check "case shuddered with a crimson flash" "__rec.shudder && __rec.flash > 0.5"
sleep 5.5
check "disc wound down to idle (rate $IDLE)" "Math.abs($rate - $IDLE) < 0.02"
check "error badge shown" "document.querySelector('#unlock-feedback').textContent.includes('WRONG_CREDENTIALS')"
check "shudder cleared" "!document.querySelector('#unseal').classList.contains('shudder')"
$D shot $OUT/06-error.png >/dev/null

$D click "button[aria-label=\"Choose another vault\"]" >/dev/null; sleep 1
check "resealed after error: error cleared" "!document.querySelector('#unlock-feedback').textContent.includes('WRONG_CREDENTIALS')"
$D click "#unseal" >/dev/null; sleep 1.4

echo "--- unlock, then lock re-seals"
$D fill "#master-password" "Onboarding-Test-2026" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
check "unlocked to dashboard" "document.querySelector('nav[aria-label=\"Vault sections\"]')"
$D click "text:Lock vault" >/dev/null
waitfor "document.querySelector('#unseal')"; sleep 0.5
check "re-sealed after lock: lid closed" "$lid === 'none' || $lid === 'matrix(1, 0, 0, 1, 0, 0)'"
check "re-sealed after lock: disc still, form inert" "$rate === 0 && $form.inert"

echo "--- auto-lock re-seals too"
$D click "#unseal" >/dev/null; $D fill "#master-password" "Onboarding-Test-2026" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
powershell -NoProfile -ExecutionPolicy Bypass -File win.ps1 post-lock >/dev/null 2>&1
waitfor "document.body.textContent.includes('AUTO-LOCKED')" 15000
sleep 0.5
check "auto-lock shows the sealed case and the reason" "document.querySelector('#unseal')?.getAttribute('aria-expanded') === 'false' && document.body.textContent.includes('AUTO-LOCKED')"
$D shot $OUT/07-autolocked.png >/dev/null
echo "=== $pass passed, $fail failed"
