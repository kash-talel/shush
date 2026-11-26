# shush — Instructions for Antigravity (AGY CLI / Gemini)

## Project Overview
`shush` is a high-security native Windows password manager built with **Tauri v2**, **Rust** backend, and **Svelte 5** (runes) frontend.

---

## Dual-Runner Architecture & Issue Routing
This project operates with a split-model workflow between **Claude Code** and **Antigravity CLI (AGY / Gemini 4 Hydrogen)**:
- **Claude Code (Sonnet 5.5 / Opus 5.5)**: Writes every line of code, UI, tests and scripts: Rust, Tauri IPC, Win32, Svelte 5, CDP/E2E scripts, assets.
- **Antigravity CLI (Gemini 4 Hydrogen)**: Prose only: documentation and spec reconciliation in Markdown files. AGY opens a PR and never merges; Claude's `/issue` dispatcher merges it after `.claude/scripts/agy-gate.ps1` confirms it only touches allowed docs.

> **Source of Truth for Routing:**
> Routing is computed from each issue's labels and title by `.claude/scripts/route-issue.ps1` (rules in `.claude/scripts/Policy.ps1`). Only Claude's `/issue` dispatcher starts AGY, inside a worktree it created, on an issue whose route is `runner: agy`.

---

## Issue Resolution Workflow (`/issue`)
Follow `.agents/skills/issue/SKILL.md`. In short:
1. **Check dispatch**: you must be in a dispatcher-made worktree, with an issue number whose route (`route-issue.ps1 -Number <N>`) is `runner: agy`. Otherwise stop.
2. **Plan**: read the issue (`.claude/scripts/issue-brief.ps1 -Number <N>`) and the specs and code it concerns, so the docs match the code.
3. **File Discovered Issues** with `gh issue create`; do not fix code yourself.
4. **Branch & Edit Markdown only**: `git checkout -B fix/issue-<N>-<slug> origin/main`. No builds, no `npm install`.
5. **PR, no merge**: commit, push, `gh pr create --body-file <file>`. Never run `gh pr merge`.
6. **Stop** after one issue with the `STATUS:` report block. Do not continue to the next issue.
