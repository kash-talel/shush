# shush — Instructions for Antigravity (AGY CLI / Gemini)

## Project Overview
`shush` is a high-security native Windows password manager built with **Tauri v2**, **Rust** backend, and **Svelte 5** (runes) frontend.

---

## Dual-Runner Architecture & Issue Routing
This project operates with a split-model workflow between **Claude Code** and **Antigravity CLI (AGY / Gemini 3.8 Flash)**:
- **Claude Code (Sonnet 5.5 / Opus 5.5)**: Handles core Win32 systems programming, high-stakes cryptographic design, and complex Tauri IPC.
- **Antigravity CLI (Gemini 3.8 Flash)**: Handles documentation reconciliation, isolated bug fixes, testing scripts (CDP/E2E), and UI/accessibility polish.

> **Source of Truth for Routing:**
> The issue mapping is maintained in `.claude/issue-routing.json`. Only Claude attributes issues to runners. AGY strictly fetches and executes issues where `runner == "agy"`.

---

## Issue Resolution Workflow (`/issue`)
When resolving issues in AGY CLI:
1. **Fetch Assigned Issue**: Run `.agents/skills/issue/scripts/get-next-issue.ps1 [-Number <N>]`. If the issue is not assigned to AGY, do not proceed.
2. **Elite Planning**: Deep dive the issue comments (`gh issue view <N> --comments`) and relevant specifications (`docs/spec/`, `docs/FORMAT.md`). Formulate a clear plan before touching code.
3. **File Discovered Issues**: If any edge case, secondary bug, or feature opportunity is spotted during work, file it immediately:
   ```powershell
   gh issue create --title "[<Category>] <Concise Title>" --body "<Details>" --label "<labels>"
   ```
4. **Branch & Verify**:
   - Branch: `git checkout -b fix/issue-<NUMBER>-<slug>`
   - Backend tests:
     ```powershell
     $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
     cargo test --manifest-path src-tauri/Cargo.toml
     ```
   - Frontend checks:
     ```powershell
     cd src; npm run check; cd ..
     ```
5. **PR & Squash-Merge**:
   - `git add <files>; git commit -m "fix(#<NUMBER>): <summary>"`
   - `git push -u origin fix/issue-<NUMBER>-<slug>`
   - `gh pr create --title "fix(#<NUMBER>): <summary>" --body "Closes #<NUMBER>..."`
   - `gh pr merge --squash --delete-branch --admin`
   - `git checkout main; git pull origin main`
6. **Queue Continuity**: Check for the next AGY issue in the queue and continue.
