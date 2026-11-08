---
name: issue
description: >-
  Resolve GitHub issues assigned to AGY (Gemini 3.8 Flash) per .claude/issue-routing.json.
  Follows the repository's elite standards: planning, reviewing, filing discovered bugs/features,
  branching, testing (cargo test & npm run check), PR, and squash-merge.
---

# AGY Issue Resolver for Shush

You are resolving GitHub issues assigned to **AGY CLI (Gemini 3.8 Flash)** for the `shush` repository.

> **CRITICAL RULE ON ISSUE ATTRIBUTION:**
> Only Claude attributes issues to models/runners. Your sole responsibility is to strictly fetch and execute the issues that Claude has attributed to AGY (`runner: agy`) in `.claude/issue-routing.json`. Never reclassify issues or execute issues assigned to Claude Sonnet or Claude Opus.

---

## Step 1: Select the Target AGY Issue
Run the helper script to select the target issue:
- If a specific issue number was requested (e.g. `48` or `#48`):
  ```powershell
  powershell -NoProfile -File .agents/skills/issue/scripts/get-next-issue.ps1 -Number <NUMBER>
  ```
  *(If this script exits with an error or GATEKEEPER ALERT indicating the issue is assigned to Claude, STOP immediately and inform the user).*
- If no issue number was provided, run without arguments to auto-pick the highest-priority AGY issue:
  ```powershell
  powershell -NoProfile -File .agents/skills/issue/scripts/get-next-issue.ps1
  ```
  *(If the output is `ALL_DONE`, report to the user that all AGY issues are resolved).*

---

## Step 2: Planning & Deep Dive
1. Inspect the issue requirements and history:
   ```powershell
   gh issue view <NUMBER> --comments
   ```
2. Inspect related specifications in `docs/spec/`, `docs/FORMAT.md`, and relevant source files (`src-tauri/src/` or `src/src/`).
3. Formulate a structured plan before making edits:
   - Identify affected modules and contracts.
   - Outline the proposed changes.
   - Define exact verification criteria.

---

## Step 3: File Discovered Bugs & Features
While analyzing the code and issue context, if you spot:
- Edge cases, secondary bugs, memory hygiene, or file format risks
- Contradictions between code and specifications
- Valuable usability, accessibility, or platform features

**Immediately file them as new GitHub issues** before or during implementation:
```powershell
gh issue create --title "[<Category>] <Concise Title>" --body "<Detailed description of problem, impact, and suggested solution>" --label "<label1>,<label2>"
```
*(Labels: `bug`, `enhancement`, `severity:critical`, `severity:high`, `severity:medium`, `severity:low`, `crypto`, `file-format`, `memory-hygiene`, `concurrency`, `os-integration`, `sync`, `spec-review`, `spec-inconsistency`).*

---

## Step 4: Implement & Verify
1. Ensure your local `main` branch is clean:
   ```powershell
   git checkout main
   git pull --autostash origin main
   ```
2. Create a dedicated feature branch:
   ```powershell
   git checkout -b fix/issue-<NUMBER>-<short-slug>
   ```
3. Implement the changes following the repo guidelines.
4. Run verification tests:
   - For backend/Rust:
     ```powershell
     $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
     cargo test --manifest-path src-tauri/Cargo.toml
     ```
   - For frontend/Svelte:
     ```powershell
     cd src; npm run check; cd ..
     ```
   Both checks must pass cleanly with 0 errors. Fix any failures before proceeding.

---

## Step 5: Commit, Push, PR, and Squash-Merge
1. Stage and commit:
   ```powershell
   git add <modified-files>
   git commit -m "fix(#<NUMBER>): <concise summary>"
   ```
2. Push branch:
   ```powershell
   git push -u origin fix/issue-<NUMBER>-<short-slug>
   ```
3. Open Pull Request:
   ```powershell
   gh pr create --title "fix(#<NUMBER>): <concise summary>" --body "Closes #<NUMBER>`n`n### Summary`n<Summary of changes>`n`n### Verification`n- [x] cargo test passed`n- [x] npm run check passed"
   ```
4. Merge the Pull Request:
   ```powershell
   gh pr merge --squash --delete-branch --admin
   ```
5. Return to main and pull:
   ```powershell
   git checkout main
   git pull --autostash origin main
   ```
6. Ensure the issue is closed on GitHub (`gh issue close <NUMBER>` if not auto-closed).

---

## Step 6: Queue Continuity & Redo
1. Print completion summary:
   ```
   ======================================================================
   ✅ COMPLETED: Issue #<NUMBER> ("<TITLE>") has been resolved and merged.
   📦 Branch cleaned up and main updated.
   ======================================================================
   ```
2. Fetch the next AGY issue in the queue:
   ```powershell
   powershell -NoProfile -File .agents/skills/issue/scripts/get-next-issue.ps1
   ```
3. If the user asked to resolve multiple issues or "keep going", immediately loop back to Step 1 for the next issue. Otherwise, present the next AGY issue to the user and ask if they would like to proceed.
