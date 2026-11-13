# shush — Instructions for Antigravity (AGY CLI / Gemini)

## Project Overview
`shush` is a high-security native Windows password manager built with **Tauri v2**, **Rust** backend, and **Svelte 5** (runes) frontend.

---

## Dual-Runner Architecture & Issue Routing
This project operates with a split-model workflow between **Claude Code** and **Antigravity CLI (AGY / Gemini 3.8 Flash)**:
- **Claude Code (Sonnet 5.5 / Opus 5.5)**: Writes every line of code, UI, tests and scripts: Rust, Tauri IPC, Win32, Svelte 5, CDP/E2E scripts, assets.
- **Antigravity CLI (Gemini 3.8 Flash)**: Prose only: documentation and spec reconciliation in Markdown files. AGY opens a PR and never merges; Claude's `/issue` dispatcher merges it after `.claude/scripts/agy-gate.ps1` confirms it only touches allowed docs.

> **Source of Truth for Routing:**
> The issue mapping is maintained in `.claude/issue-routing.json`. Only Claude attributes issues to runners. AGY strictly fetches and executes issues where `runner == "agy"`.

---

## Issue Resolution Workflow (`/issue`)
Follow `.agents/skills/issue/SKILL.md`. In short:
1. **Fetch Assigned Issue**: `.agents/skills/issue/scripts/get-next-issue.ps1 [-Number <N>]`. If the issue is not assigned to AGY, do not proceed.
2. **Plan**: read the issue (`gh issue view <N> --comments`) and the specs and code it concerns, so the docs match the code.
3. **File Discovered Issues** with `gh issue create`; do not fix code yourself.
4. **Branch & Edit Markdown only**: `git checkout -B fix/issue-<N>-<slug> origin/main`. No builds, no `npm install`.
5. **PR, no merge**: commit, push, `gh pr create`. Never run `gh pr merge`.
6. **Stop** after one issue with the `STATUS:` report block. Do not continue to the next issue.
