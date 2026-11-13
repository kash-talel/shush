---
name: issue
description: >-
  Resolve ONE GitHub issue assigned to AGY (Gemini 3.8 Flash) per .claude/issue-routing.json.
  AGY gets prose-only work (docs and specs): plan, file discovered issues, branch, edit Markdown,
  open a PR. AGY never merges; Claude's /issue dispatcher gates and merges the PR.
---

# AGY Issue Resolver for Shush

You are resolving a GitHub issue assigned to **AGY CLI (Gemini 3.8 Flash)** for the `shush` repository.

> **SCOPE: MARKDOWN ONLY.** Change only `.md` files (docs, specs). Never edit code, tests,
> scripts, assets, or config, nothing under `.claude/`, `.agents/`, `.github/` or `.cargo/`, and never
> `CLAUDE.md`, `GEMINI.md`, `AGENTS.md` or `SECURITY.md`. The merge gate
> (`.claude/scripts/agy-gate.ps1`) rejects any PR that does. If the issue cannot be solved in
> docs alone, stop with `STATUS: BLOCKED` and say it needs Claude.

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
2. Read the related specifications in `docs/spec/`, `docs/FORMAT.md`, and any source files the
   docs describe (`src-tauri/src/` or `src/src/`), so what you write matches the code.
3. Plan before editing: which documents change, what each change says, and how you will check it.

---

## Step 3: File Discovered Bugs & Features
If you spot edge cases, secondary bugs, memory-hygiene or file-format risks, contradictions
between code and specifications, or valuable features, file them as new GitHub issues:
```powershell
gh issue create --title "[<Category>] <Concise Title>" --body "<Detailed description of problem, impact, and suggested solution>" --label "<label1>,<label2>"
```
*(Labels: `bug`, `enhancement`, `severity:critical`, `severity:high`, `severity:medium`, `severity:low`, `crypto`, `file-format`, `memory-hygiene`, `concurrency`, `os-integration`, `sync`, `spec-review`, `spec-inconsistency`).*
Do not fix code problems yourself; filing them is the job.

---

## Step 4: Branch, Edit & Check
1. Branch from a fresh `origin/main` (works in a normal checkout and in an `/issue` worktree;
   never `git checkout main`, which fails inside a worktree):
   ```powershell
   git fetch origin main
   git checkout -B fix/issue-<NUMBER>-<short-slug> origin/main
   ```
2. Edit the Markdown files. Do not build, launch the app, or run `npm install` / `npm ci` /
   `npm update` (`src/node_modules` may be a junction into the owner's checkout).
3. Check your work: every link and file path you mention exists (`Test-Path`), headings and
   tables render, and statements about code match the code you read.

---

## Step 5: Commit, Push, and Open the PR
1. Stage and commit only the Markdown files you changed:
   ```powershell
   git add <modified-files>
   git commit -m "docs(#<NUMBER>): <concise summary>"
   ```
2. Push branch:
   ```powershell
   git push -u origin fix/issue-<NUMBER>-<short-slug>
   ```
3. Open Pull Request:
   ```powershell
   gh pr create --title "docs(#<NUMBER>): <concise summary>" --body "Closes #<NUMBER>`n`n### Summary`n<Summary of changes>`n`n### Checks`n- [x] links and paths verified"
   ```
4. **Do not merge.** Never run `gh pr merge`, with or without `--admin`. The Claude `/issue`
   dispatcher runs `agy-gate.ps1` on your PR and merges it only if it touches allowed docs.
5. Do not switch branches or close the issue; `Closes #<NUMBER>` closes it on merge.

---

## Step 6: Stop
Resolve exactly one issue per run. Do not fetch, offer or start the next issue. End with:
```
STATUS: DONE | BLOCKED | FAILED
ISSUE: #<NUMBER>
PR: <url or none>
FILED: <new issue numbers or none>
SUMMARY: <2-4 lines>
```
