---
name: issue
description: Resolve a single GitHub issue for the shush repository by routing it (.claude/issue-routing.json) and dispatching it to its assigned model - a Sonnet or Opus issue-worker subagent, or headless AGY CLI (Gemini 3.8 Flash) - then report and prompt for /clear.
model: haiku
disable-model-invocation: true
---

# /issue: route and dispatch one shush issue

You are the dispatcher. You pick ONE issue, look up its assigned runner and model, hand the whole
job to that runner, and report the result. You never read code, edit files, branch, or run tests
yourself: the runner does all of that on its own model, so the expensive work is billed at the
right tier and this session stays cheap.

Input arguments: $ARGUMENTS

## Step 1: Preflight
Run `git status --porcelain`. Ignore `.claude/issue-routing.json` (routing lookups update it).
If any other file is modified or untracked, STOP and print:
```
⛔ Working tree is not clean. /issue runners switch branches and pull main, which would carry
   these changes along. Commit, stash, or move them first:
   <list the files>
```

## Step 2: Select and route the issue
Routing is a single call per issue; it classifies new issues once and saves them:
```powershell
powershell -NoProfile -File .claude/scripts/route-issue.ps1 -Number <NUMBER>
```
It prints JSON with `number`, `title`, `model`, `runner` (`claude` | `agy`) and `target`
(`opus` | `sonnet` | an agy model id such as `gemini-3.8-flash-medium`).

- If `$ARGUMENTS` contains an issue number (`20` or `#20`), route that issue.
- Otherwise run `gh issue list --state open --limit 200 --json number,title,labels`, sort by
  `severity:critical` > `severity:high` > `severity:medium` > `severity:low` > no severity, then
  lowest number, and route the first one. Every runner is handled, so do not skip any issue.
- If there are no open issues, say so and stop.

If `runner` is not `claude` or `agy`, or `target` is empty, STOP and show the JSON: the routing
entry was edited by hand and needs fixing. Never guess a runner.

Print one line before dispatching:
`🧭 Issue #<NUMBER> ("<TITLE>") → <runner> / <target>`

## Step 3: Dispatch to the assigned runner

### runner `claude` → issue-worker subagent on the routed model
Call the Agent tool with:
- `subagent_type`: `"issue-worker"`
- `model`: the `target` value (`"opus"` or `"sonnet"`), exactly as routed. Never substitute.
- `description`: `"Resolve issue #<NUMBER>"`
- `prompt`: `Resolve issue #<NUMBER> ("<TITLE>"). It is routed to <model>. Follow your procedure and end with the Final report block.`

Wait for the subagent's completion notification. Do not do anything else meanwhile, and never
guess its result.

### runner `agy` → AGY CLI headless
Run this with the Bash tool, `run_in_background: true` (it can run longer than 10 minutes), from
the repository root:
```bash
agy -p "/issue <NUMBER>. Resolve only this issue: do not pick up or offer the next AGY issue. Finish your reply with exactly these lines: STATUS: DONE|BLOCKED|FAILED, ISSUE: #<NUMBER>, PR: <url or none>, FILED: <new issue numbers or none>, SUMMARY: <2-4 lines>." --model <target> --output-format text
```
Do not add `--mode auto`: it is not available on this account (agy warns and falls back). The
default mode already lets headless agy write files and run shell commands.
Wait for the background-command notification, then read its output. Do not poll it.
If the output has no `STATUS:` line (agy crashed, hit a limit, or ignored the format), treat it
as FAILED and rely on the GitHub check in Step 4.

## Step 4: Verify and record
1. Check the outcome on GitHub rather than trusting the report alone:
   `gh issue view <NUMBER> --json state,closedByPullRequestsReferences`
2. For each issue number in `FILED`, run `route-issue.ps1 -Number <N>` so new issues are routed
   right away.
3. If `STATUS` is BLOCKED or FAILED, or the issue is still open, print the runner's report verbatim
   under `⚠️ Issue #<NUMBER> was not completed by <runner>/<target>:` and stop. Do not retry on
   another model unless the user asks.

## Step 5: Stop and prompt for /clear
**STOP HERE.** Do not start another issue. Print:
```
======================================================================
✅ COMPLETED: Issue #<NUMBER> ("<TITLE>") resolved by <runner>/<target>, PR merged.
🔗 PR: <url>
🆕 Filed & routed: <numbers or none>
💡 ACTION REQUIRED: Type `/clear` now to wipe context tokens before running `/issue` again!
======================================================================
```
