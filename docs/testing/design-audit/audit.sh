#!/usr/bin/env bash
# UI audit walk over CDP. Usage: audit.sh <out dir>   (expects a fresh scratch vault: no vault.shush yet)
# Drives every major view and saves a screenshot of each. No mouse/keyboard input.
set -uo pipefail
cd "$(dirname "$0")"
OUT="$1"; mkdir -p "$OUT"
D="node cdp.mjs"
S="env CDP_WINDOW=spotlight node cdp.mjs"
waitfor() { $D wait "$1" "${2:-20000}" >/dev/null || echo "TIMEOUT waiting for: $1"; }
shot() { $D shot "$OUT/$1.png" >/dev/null && echo "shot $1"; }
PW="Crimson-Vinyl-2026!"

$D eval "location.reload()" >/dev/null; sleep 2
waitfor "document.querySelector('#new-password')"
shot 01-create
$D fill "#new-password" "$PW" >/dev/null
$D fill "#confirm-password" "$PW" >/dev/null
$D click "details summary" >/dev/null
$D click "input[type=checkbox]" >/dev/null
shot 02-create-filled
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('[aria-label=\"Browsers found on this PC\"]') || document.body.textContent.includes('No supported browser')" 40000
sleep 1; shot 03-onboarding
$D click "text:SKIP FOR NOW" >/dev/null
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')"
shot 04-dashboard-empty

# folder
$D click "[aria-label=\"New folder\"]" >/dev/null; sleep 0.3
$D fill "[aria-label=\"Folder name\"]" "Work" >/dev/null
$D click "[aria-label=\"Save folder\"]" >/dev/null; sleep 0.5

# login with generator + TOTP
$D click "text:New login" >/dev/null
waitfor "document.querySelector('#f-title')"
$D fill "#f-title" "GitHub" >/dev/null
$D fill "#f-username" "octocat@example.com" >/dev/null
$D click "text:Generate password" >/dev/null
waitfor "document.querySelector('output')?.textContent.trim().length >= 20"
$D fill "#f-url" "https://github.com/login" >/dev/null
$D fill "#f-tags" "dev, work" >/dev/null
shot 05-editor-generator
$D click "text:USE THIS PASSWORD" >/dev/null
$D click "#f-totp" >/dev/null; waitfor "document.querySelector('input#f-totp')"
$D fill "#f-totp" "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'GitHub'"
$D click "[aria-label=\"Add to favorites\"]" >/dev/null; sleep 0.3

# more items
for t in "Proton Mail|me@proton.me|https://account.proton.me" "Hetzner Cloud|ops@shush.dev|https://console.hetzner.cloud" "Bank of Tunis|m.ghozzi|https://ebanking.example.tn"; do
  IFS='|' read -r title user url <<<"$t"
  $D click "text:New login" >/dev/null; waitfor "document.querySelector('#f-title')"
  $D fill "#f-title" "$title" >/dev/null; $D fill "#f-username" "$user" >/dev/null; $D fill "#f-url" "$url" >/dev/null
  $D fill "#f-password" "correct-horse-battery-$RANDOM" >/dev/null
  $D click "button[type=submit]" >/dev/null
  waitfor "document.querySelector('article h2')?.textContent === '$title'"
done
$D click "text:New secure note" >/dev/null; waitfor "document.querySelector('#f-title')"
$D fill "#f-title" "Recovery codes" >/dev/null
$D eval "(() => { const t = document.querySelector('#f-content'); const s = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set; s.call(t, 'github: 4f2a-91c0\nproton: 77d1-0be3\nhetzner: c0de-5eed'); t.dispatchEvent(new Event('input',{bubbles:true})); return 1 })()" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'Recovery codes'"
shot 06-note
$D click "text:GitHub" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'GitHub'"
waitfor "/\\d{3} \\d{3}/.test(document.querySelector('[aria-label=\"Copy one-time code\"]')?.textContent ?? '')"
shot 07-detail-totp
$D click "[aria-label=\"Reveal password\"]" >/dev/null; sleep 0.4
shot 08-detail-revealed
$D click "[aria-label=\"Hide password\"]" >/dev/null
$D click "text:Delete" >/dev/null; sleep 0.2
shot 09-delete-confirm
$D eval "document.activeElement?.blur(); 1" >/dev/null

$D click "text:Backup & import" >/dev/null; sleep 0.5
shot 10-backup
$D click "text:Separate password" >/dev/null; sleep 0.3
shot 11-backup-dedicated

# Spotlight (rendered in its own window; shown only for the capture, then hidden via IPC)
$D click "text:Quick search" >/dev/null; sleep 1.2
$S shot "$OUT/12-spotlight.png" >/dev/null && echo "shot 12-spotlight"
$S fill "input" "hub" >/dev/null; sleep 0.3
$S shot "$OUT/13-spotlight-query.png" >/dev/null && echo "shot 13-spotlight-query"
$S eval "window.__TAURI_INTERNALS__.invoke('hide_spotlight').then(() => 1)" >/dev/null

# min window size
$D eval "1" >/dev/null
node -e "
const port=9222;(async()=>{const t=await (await fetch('http://127.0.0.1:'+port+'/json')).json();const p=t.find(x=>x.type==='page'&&/localhost:1420|tauri\.localhost/.test(x.url)&&x.title!=='shush quick search');
const ws=new WebSocket(p.webSocketDebuggerUrl);await new Promise(r=>ws.onopen=r);let i=0;const send=(m,pa={})=>new Promise(r=>{const id=++i;ws.addEventListener('message',e=>{const d=JSON.parse(e.data);if(d.id===id)r(d)});ws.send(JSON.stringify({id,method:m,params:pa}))});
await send('Emulation.setDeviceMetricsOverride',{width:720,height:560,deviceScaleFactor:1,mobile:false});await new Promise(r=>setTimeout(r,500));
const s=await send('Page.captureScreenshot',{format:'png'});require('fs').writeFileSync(process.argv[1],Buffer.from(s.result.data,'base64'));
await send('Emulation.clearDeviceMetricsOverride');ws.close();})()" "$OUT/14-min-size.png" && echo "shot 14-min-size"

# lock → unlock screen, wrong password
$D click "text:Lock vault" >/dev/null
waitfor "document.querySelector('#master-password')"
shot 15-unlock
$D fill "#master-password" "wrong-password" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.body.textContent.includes('WRONG_CREDENTIALS')" 30000
shot 16-unlock-error
$S shot "$OUT/17-spotlight-locked.png" >/dev/null && echo "shot 17-spotlight-locked (hidden window render)"
echo done
