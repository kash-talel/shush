# Single GitHub Issue Resolver for Shush

You are resolving a single GitHub issue for the `shush` repository.

Input arguments: $ARGUMENTS

Follow this strict step-by-step procedure:

## Step 1: Select the Target Issue
- If "$ARGUMENTS" contains an issue number (e.g. "20" or "#20"), target that specific issue.
- Otherwise, run:
  ```powershell
  gh issue list --state open --limit 50 --json number,title,labels
  ```
  Sort the open issues by priority:
  1. `severity:critical` (Highest)
  2. `severity:high`
  3. `severity:medium`
  4. `severity:low`
  *(If multiple have the same severity, pick the lowest issue number).*

  Then select the first issue in that order whose runner is `claude`:
  1. For each candidate in priority order, run `powershell -NoProfile -File .claude/scripts/route-issue.ps1 -Number <NUMBER>` and read its `runner`. New issues are classified and saved on the first lookup.
  2. Stop at the first candidate with runner `claude`. Every candidate before it is an `agy` issue that was skipped.
  3. For each skipped `agy` issue, print this notice, filling in the skipped number and the selected number:
     `💡 Note: Issue #<NUM> is mapped to AGY CLI. Auto-selecting next highest Claude issue #<NUM>.`
  4. If no open issue has runner `claude`, stop and report that no issue is currently routed to Claude.

## Step 1.5: Model & Runner Gatekeeper
Look up the routing for the selected issue (it is classified once and saved in `.claude/issue-routing.json`). An auto-picked issue is already `claude` from Step 1, so this gate stops only an explicit `/issue <NUMBER>` that maps to `agy`:
```powershell
powershell -NoProfile -File .claude/scripts/route-issue.ps1 -Number <NUMBER>
```
The script prints JSON with `title`, `model`, and `runner`. Act on it:
- **If `runner` is `agy`:** STOP immediately. Do not modify code, create branches, file issues, or run any later step. Print this block with `<NUMBER>` and `<TITLE>` filled in, then end the turn:
  ```
  ======================================================================
  ⚡ TOKEN OPTIMIZATION GATE: RUN IN AGY CLI (Gemini 3.8 Flash)
  Issue #<NUMBER> ("<TITLE>") is mapped to Gemini 3.8 Flash.
  Running this in Claude will consume unnecessary high-cost tokens.
  👉 Switch to AGY CLI and execute:
     agy "resolve issue #<NUMBER>"
  ======================================================================
  ```
- **If `runner` is `claude` and `model` is `claude-opus-5.5`:** print "⚠️ This issue involves complex cryptography/concurrency. Ensure your active Claude model is set to Opus before proceeding." Then continue to Step 2.
- **If `runner` is `claude` and `model` is `claude-sonnet-5.5`:** proceed to Step 2.

## Step 2: Deep Dive the Selected Issue
1. Inspect the issue requirements and history:
   ```powershell
   gh issue view <NUMBER> --comments
   ```
2. Inspect related specifications in `docs/spec/`, `docs/FORMAT.md`, and the relevant code files (`src-tauri/src/` or `src/src/`).
3. Check if an installed skill applies (e.g. `svelte-core-bestpractices`, `frontend-design`, `native-feel-cross-platform-desktop`). If the task involves a new tool, stack component, or testing workflow without an installed skill, invoke `find-skills` per `CLAUDE.md` to search and vet candidate skills before proceeding.

## Step 3: File Discovered Bugs & Feature Suggestions
If during your analysis, review, or implementation you discover:
- Secondary bugs, edge cases, or potential memory/crypto risks
- Inconsistencies between specs and code
- High-value feature ideas or usability improvements

**Immediately file them as new GitHub issues** before or during implementation:
```powershell
gh issue create --title "[<Category>] <Concise Title>" --body "<Detailed description of problem, impact, and suggested solution>" --label "<label1>,<label2>"
```
*(Use appropriate labels: `bug`, `enhancement`, `severity:critical`, `severity:high`, `severity:medium`, `severity:low`, `crypto`, `file-format`, `memory-hygiene`, `concurrency`, `os-integration`, `sync`, `spec-review`, `spec-inconsistency`).*

## Step 4: Implement & Verify
1. Ensure your local `main` branch is clean:
   ```powershell
   git checkout main
   git pull origin main
   ```
2. Create a dedicated branch:
   ```powershell
   git checkout -b fix/issue-<NUMBER>-<short-slug>
   ```
3. Implement the necessary code and/or documentation changes following the standards in `CLAUDE.md`.
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
   All tests and checks must pass with 0 errors. Fix any failures before proceeding.

## Step 5: Commit, Push, PR, and Merge
1. Commit the changes:
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
5. Checkout main and pull:
   ```powershell
   git checkout main
   git pull origin main
   ```
6. Verify the issue is closed (run `gh issue close <NUMBER>` if not automatically closed).

## Step 6: Stop & Instruct Token Reset
**STOP HERE.** Do not start another issue.
Print a clear final summary in this exact format:
```
======================================================================
✅ COMPLETED: Issue #<NUMBER> ("<TITLE>") has been resolved, PR opened, and merged.
📦 Branches cleaned and main updated.
💡 ACTION REQUIRED: Type `/clear` now to wipe context tokens before running `/issue` again!
======================================================================
```
