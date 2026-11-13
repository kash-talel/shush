---
name: issue
description: Resolve a single GitHub issue for the shush repository by routing it (.claude/issue-routing.json) and dispatching it to its assigned model - a Sonnet or Opus issue-worker subagent, or headless AGY CLI (Gemini 3.8 Flash) - in an isolated git worktree, then report and prompt for /clear.
model: haiku
disable-model-invocation: true
---

# /issue: route and dispatch one shush issue

You are the dispatcher. You pick ONE issue, look up its assigned runner and model, hand the whole
job to that runner in an isolated git worktree, and report the result. You never read code, edit
files, branch, or run tests yourself: the runner does that on its own model, so the expensive work
is billed at the right tier and this session stays cheap.

Every runner works in its own worktree checked out from `origin/main`. The owner's main checkout
is never switched, stashed, or edited, so uncommitted work there is safe and does not block a run.

Input arguments: $ARGUMENTS

**One issue per session.** If this conversation already contains a `✅ COMPLETED` or
`⚠️ Issue #` banner from an earlier `/issue`, do nothing except tell the user to type `/clear`
first. Context carried from one issue into the next is re-read on every later call, which is how
earlier sessions burned over a billion cached tokens.

## Step 1: Select and route the issue
Routing is a single call per issue; it classifies new issues once and saves them:
```powershell
powershell -NoProfile -File .claude/scripts/route-issue.ps1 -Number <NUMBER>
```
It prints JSON with `number`, `title`, `model`, `runner` (`claude` | `agy`), `target`
(`opus` | `sonnet` | an agy model id such as `gemini-3.8-flash-medium`), and `merge`
(`auto` | `review`) with `merge_reason`. `review` means the owner merges the PR by hand.

First list the issues that already have a PR waiting for the owner:
`gh pr list --state open --label needs-review --json number,headRefName`
(heads look like `fix/issue-<N>-<slug>`). Those issues are parked until the owner merges or closes
that PR; never start a second run on them.

- If `$ARGUMENTS` contains an issue number (`20` or `#20`), route that issue. If it is parked,
  print `⏸️ Issue #<N> already has PR #<PR> awaiting your review` and stop.
- Otherwise run `gh issue list --state open --limit 200 --json number,title,labels`, drop the
  parked issues, sort by `severity:critical` > `severity:high` > `severity:medium` >
  `severity:low` > no severity, then lowest number, and route the first one. Every runner is
  handled, so do not skip any other issue.
- If there are no open issues left, say so and stop.

If `runner` is not `claude` or `agy`, `target` is empty, or `merge` is not `auto` or `review`,
STOP and show the JSON: the routing entry was edited by hand and needs fixing. Never guess.

Print one line before dispatching:
`🧭 Issue #<NUMBER> ("<TITLE>") → <runner> / <target> · merge: <merge> (<merge_reason>)`

## Step 2: Dispatch to the assigned runner

### runner `claude` → issue-worker subagent on the routed model
Call the Agent tool with:
- `subagent_type`: `"issue-worker"`
- `model`: the `target` value (`"opus"` or `"sonnet"`), exactly as routed. Never substitute.
- `isolation`: `"worktree"`
- `description`: `"Resolve issue #<NUMBER>"`
- `prompt`: `Resolve issue #<NUMBER> ("<TITLE>"). It is routed to <model>. Merge policy: <merge>. Follow your procedure and end with the Final report block.`

Wait for the subagent's completion notification. Do not do anything else meanwhile, and never
guess its result. The worktree path is in the notification and in the report's `WORKTREE:` line.

### runner `agy` → AGY CLI headless, in a worktree you create
1. Create the worktree; the script prints its path:
   ```powershell
   powershell -NoProfile -File .claude/scripts/issue-worktree.ps1 -Create -Number <NUMBER>
   ```
   If it says the worktree already exists, a previous run was interrupted: remove it with
   `-Remove -Path <that path>` and create it again.
2. Run agy from inside that worktree with the Bash tool, `run_in_background: true` (it can run
   longer than 10 minutes):
   ```bash
   cd "<WORKTREE>" && agy -p "/issue <NUMBER>. Resolve only this issue: do not pick up or offer the next AGY issue. Change only Markdown docs. Push your branch and open the PR, but do NOT merge it; the dispatcher gates and merges. Finish your reply with exactly these lines: STATUS: DONE|BLOCKED|FAILED, ISSUE: #<NUMBER>, PR: <url or none>, FILED: <new issue numbers or none>, SUMMARY: <2-4 lines>." --model <target> --output-format text
   ```
   Do not add `--mode auto`: it is not available on this account (agy warns and falls back), and
   the default mode already lets headless agy write files and run shell commands.
3. Wait for the background-command notification, then read its output. Do not poll it.
   If the output has no `STATUS:` line (agy crashed, hit a limit, or ignored the format), treat it
   as FAILED and rely on the GitHub check in Step 3.
4. Find agy's PR: the `PR:` line, or if missing,
   `gh pr list --state open --json number,url,headRefName --jq '.[] | select(.headRefName | startswith("fix/issue-<NUMBER>-"))'`.
   If there is one, gate it, and merge only when the policy is `auto`:
   ```powershell
   powershell -NoProfile -File .claude/scripts/agy-gate.ps1 -Pr <PR number> -Merge   # merge: auto
   powershell -NoProfile -File .claude/scripts/agy-gate.ps1 -Pr <PR number>          # merge: review
   ```
   Exit 0 = passed (and merged, with `-Merge`). For `review`, then run
   `gh pr edit <PR number> --add-label needs-review` and treat the run as `STATUS: REVIEW`.
   Exit 3 = rejected: the PR touched something other than Markdown docs; it is left open with a
   comment, and you report the issue as not completed. Never merge an AGY PR any other way, and
   never with `--admin` by hand.

## Step 3: Verify, clean up, record
1. Check the outcome on GitHub rather than trusting the report alone:
   `gh issue view <NUMBER> --json state,closedByPullRequestsReferences`
   For `STATUS: REVIEW`, instead confirm the PR is open and labelled:
   `gh pr view <PR> --json state,labels,headRefName`. If it is not open with `needs-review`,
   treat the run as FAILED.
2. Remove the worktree, but ONLY if the issue is now closed by a merged PR, or the run is a
   confirmed REVIEW (its branch is pushed, so the PR holds the work and the cargo slot is freed
   for the next run). A failed or blocked run keeps its worktree so the work can be inspected or
   resumed:
   ```powershell
   powershell -NoProfile -File .claude/scripts/issue-worktree.ps1 -Remove -Path "<WORKTREE>"
   git branch -D fix/issue-<NUMBER>-<short-slug>   # local branch, if one is left; ignore "not found"
   ```
   Always use the script, never a bare `git worktree remove` or `rm -r`: the worktree holds
   junctions to main's `node_modules` and to a leased cargo target slot. The script stops
   processes still holding files in the worktree, unlinks the junctions, and releases the slot
   so the next run reuses its compiled dependencies.
3. Bring the main checkout up to date without touching uncommitted work:
   `git fetch origin main`, then, only if the current branch is `main`, `git merge --ff-only origin/main`.
   If that refuses (local changes overlap the incoming files), leave it and mention it in the summary.
4. For each issue number in `FILED`, run `route-issue.ps1 -Number <N>` so new issues are routed
   right away.
5. If `STATUS` is REVIEW (confirmed), print the Step 4 banner with its REVIEW lines.
   If `STATUS` is BLOCKED or FAILED, or the issue is still open without a confirmed REVIEW PR,
   print the runner's report verbatim
   under `⚠️ Issue #<NUMBER> was not completed by <runner>/<target>:`, add
   `Worktree kept at <WORKTREE>`, and stop. Do not retry on another model unless the user asks.

## Step 4: Stop and prompt for /clear
**STOP HERE.** Do not start another issue. Print this banner. For a REVIEW run, replace the
first line with `🔍 AWAITING YOUR REVIEW: Issue #<NUMBER> ("<TITLE>") by <runner>/<target>, PR open (<merge_reason>).`
and add, after the PR line, `👀 Review, then merge: gh pr merge <PR> --squash --delete-branch`.
```
======================================================================
✅ COMPLETED: Issue #<NUMBER> ("<TITLE>") resolved by <runner>/<target>, PR merged.
🔗 PR: <url>
🆕 Filed & routed: <numbers or none>
🧩 Skill suggestion: <the worker's SKILLS line, or none> (run /find-skills yourself if you want it)
🧹 Worktree removed; main <fast-forwarded | not updated: reason>
💡 ACTION REQUIRED: Type `/clear` now to wipe context tokens before running `/issue` again!
======================================================================
```
