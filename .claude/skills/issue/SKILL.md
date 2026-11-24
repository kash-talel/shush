---
name: issue
description: Resolve a single GitHub issue for the shush repository - pick and route it (issue-next.ps1), dispatch it to its runner (Sonnet or Opus issue-worker subagent, or headless AGY CLI) in an isolated git worktree, send sensitive PRs through an Opus pr-reviewer, then check the outcome and print the banner (issue-finish.ps1) and prompt for /clear.
model: haiku
disable-model-invocation: true
---

# /issue: route and dispatch one shush issue

You are the dispatcher. Scripts make every decision; you run them, hand the work to the runner
they name, and pass results back. You never read code, edit repo files, branch, or run tests.
The owner's main checkout is never switched, stashed, or edited.

Input arguments: $ARGUMENTS

**One issue per session.** If this conversation already contains a `COMPLETED`,
`YOUR DECISION NEEDED`, `APPROVED, NOT MERGED` or `was not completed` banner, do nothing except tell the user to type
`/clear` first.

## Step 1: Pick
```powershell
powershell -NoProfile -File .claude/scripts/issue-next.ps1            # or -Number <N> if $ARGUMENTS names one
```
It prints one JSON line. Print: `🧭 Issue #<number> ("<title>") → <runner> / <target> · merge: <merge> (<merge_reason>) <note>`
Then by `action`:
- `none`: say so and stop.
- `parked`: print `⏸️ Issue #<number> already has PR #<pr> awaiting your decision` and stop.
- `review`: go to Step 3 with `pr`.
- `resume-pr`: an open PR already exists. runner `agy` → Step 2 AGY item 4 with `pr`.
  runner `claude` → `powershell -NoProfile -File .claude/scripts/merge-pr.ps1 -Pr <pr>`:
  exit 0 → Step 4; exit 4 → Step 3; any other exit → Step 2 claude, adding to the prompt
  `An open PR #<pr> on branch <head> already exists: continue from it.`
- `dispatch`: Step 2.

If `runner` is not `claude`/`agy` or `target` is empty, STOP and show the JSON. Never guess.

## Step 2: Dispatch
**runner `claude`** → Agent tool: `subagent_type: "issue-worker"`, `model: <target>` exactly,
`isolation: "worktree"`, `description: "Resolve issue #<number>"`, `prompt:`
`Resolve issue #<number> ("<title>"). Merge policy: <merge>. Follow your procedure and end with the Final report block.`
Wait for the completion notification; never guess its result. Save the report block verbatim
with the Write tool to `<scratchpad>\worker-<number>.txt`. `STATUS: REVIEW` → Step 3, else Step 4.

**runner `agy`**:
1. `powershell -NoProfile -File .claude/scripts/issue-worktree.ps1 -Create -Number <number>` prints the
   worktree path (if it already exists, `-Remove -Path <it>` and create again).
2. Bash tool, `run_in_background: true`:
   ```bash
   cd "<WORKTREE>" && agy -p "/issue <number>. Resolve only this issue. Change only Markdown docs. Push your branch and open the PR, but do NOT merge it. Finish with exactly these lines: STATUS: DONE|BLOCKED|FAILED, ISSUE: #<number>, PR: <url or none>, FILED: <numbers or none>, SUMMARY: <2-4 lines>." --model <target> --output-format text
   ```
   Do not add `--mode auto` (not available on this account).
3. Wait for the notification; never poll. Save the output's report lines to `<scratchpad>\worker-<number>.txt`
   (no `STATUS:` line → write `STATUS: FAILED` plus the last lines of output).
4. PR = the `PR:` line, or `gh pr list --state open --json number,headRefName --jq '.[] | select(.headRefName | startswith("fix/issue-<number>-")) | .number'`.
   If there is one: `powershell -NoProfile -File .claude/scripts/agy-gate.ps1 -Pr <pr>` (add `-Review` when merge is `review`).
   Exit 0 merged → Step 4. Exit 4 → Step 3. Anything else → Step 4 (the script already commented/closed).
   Never merge an AGY PR any other way.

## Step 3: Independent review
Agent tool: `subagent_type: "pr-reviewer"`, `model: "opus"` always, `isolation: "worktree"`,
`description: "Review PR #<pr>"`, `prompt:`
`Review PR #<pr> for issue #<number> ("<title>"). It needs review because: <merge_reason>. Follow your procedure and end with the Final report block.`
Wait for the notification. Save its report verbatim to `<scratchpad>\review-<number>.txt`.

## Step 4: Finish
```powershell
powershell -NoProfile -File .claude/scripts/issue-finish.ps1 -Number <number> -Runner <runner> -Target <target> -Report "<worker file>","<review file if any>" [-Worktree "<agy worktree>"]
```
It checks the result on GitHub, labels failures so they are not picked again, removes finished
worktrees, fast-forwards main, and prints the banner. Print its output verbatim and **STOP**.
Do not start another issue, and do not retry on another model unless the user asks.
