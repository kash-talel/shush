#!/usr/bin/env bash
# Phase 4b e2e (folders). Usage: e2e-phase4b.sh <scratchpad dir>   (vault: e2e7, password only)
set -uo pipefail
cd "$1"
D="node cdp.mjs"
pass=0; fail=0
check() { if [ "$($D eval "!!($2)")" = "true" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; fail=$((fail+1)); fi; }
waitfor() { $D wait "$1" "${2:-15000}" >/dev/null || echo "TIMEOUT waiting for: $1"; }
body="document.body.textContent"
folders="[...document.querySelectorAll('[aria-label=Folders] button[aria-current], [aria-label=Folders] .group > button:first-child')].map(b => b.textContent.replace(/\\s+/g,' ').trim())"
opts="[...document.querySelectorAll('[role=option]')]"

echo "--- unlock"
if [ "$($D eval "!!document.querySelector('#master-password')")" = "true" ]; then
  $D click "#unseal" >/dev/null; $D fill "#master-password" "Onboarding-Test-2026" >/dev/null
  $D click "button[type=submit]" >/dev/null
fi
waitfor "document.querySelector('nav[aria-label=\"Vault sections\"]')" 30000
check "dashboard open, folders section shown" "document.querySelector('[aria-label=Folders]')"

echo "--- create folder + duplicate rejected"
$D click "[aria-label=\"New folder\"]" >/dev/null
waitfor "document.querySelector('[aria-label=\"Folder name\"]')"
$D fill "[aria-label=\"Folder name\"]" "Work" >/dev/null
$D click "[aria-label=\"Save folder\"]" >/dev/null
waitfor "$folders.some(t => t.startsWith('Work'))"
check "folder 'Work' created with 0 items" "$folders.some(t => t === 'Work 0')"
$D click "[aria-label=\"New folder\"]" >/dev/null
$D fill "[aria-label=\"Folder name\"]" "work" >/dev/null
$D click "[aria-label=\"Save folder\"]" >/dev/null
waitfor "$body.includes('already exists')"
check "case-insensitive duplicate rejected" "$body.includes('A folder with that name already exists')"
$D click "[aria-label=\"Cancel\"]" >/dev/null

echo "--- new login inside the selected folder"
$D click "text:Work" >/dev/null
check "folder filter shows empty list" "$opts.length === 0"
$D click "text:New login" >/dev/null
waitfor "document.querySelector('#f-folder')"
check "editor pre-selects the current folder" "document.querySelector('#f-folder').selectedOptions[0].textContent === 'Work'"
$D fill "#f-title" "Jira" >/dev/null
$D fill "#f-password" "jira-pw" >/dev/null
$D click "button[type=submit]" >/dev/null
waitfor "document.querySelector('article h2')?.textContent === 'Jira'"
check "item listed in folder" "$opts.length === 1 && $opts[0].textContent.includes('Jira')"
check "detail shows folder chip" "document.querySelector('[aria-label=Folder]')?.textContent.includes('Work')"
check "folder count is 1" "$folders.some(t => t === 'Work 1')"

echo "--- rename"
$D click "[aria-label=\"Rename Work\"]" >/dev/null
waitfor "document.querySelector('[aria-label=\"Folder name\"]')"
$D fill "[aria-label=\"Folder name\"]" "Office" >/dev/null
$D click "[aria-label=\"Save folder\"]" >/dev/null
waitfor "$folders.some(t => t.startsWith('Office'))"
check "renamed to Office, chip follows" "$folders.some(t => t === 'Office 1') && document.querySelector('[aria-label=Folder]')?.textContent.includes('Office')"
$D shot shots/p4b-01-folders.png >/dev/null

echo "--- delete folder keeps its items"
$D click "[aria-label=\"Delete Office\"]" >/dev/null
check "first click only arms delete" "document.querySelector('[aria-label^=\"Click again to delete Office\"]') && $folders.length === 1"
$D click "[aria-label^=\"Click again to delete Office\"]" >/dev/null
waitfor "$folders.length === 0"
check "folder removed" "$folders.length === 0 && $body.includes('No folders yet')"
check "view fell back to All items, login still there" "$opts.some(o => o.textContent.includes('Jira'))"
check "detail no longer shows a folder" "document.querySelector('article h2')?.textContent === 'Jira' && !document.querySelector('[aria-label=Folder]')"

echo "=== $pass passed, $fail failed"
[ "$fail" -eq 0 ]
