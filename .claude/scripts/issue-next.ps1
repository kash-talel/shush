# Step 1 of /issue: decide what to work on, deterministically. Prints ONE JSON line.
#
# Usage:  powershell -NoProfile -File .claude/scripts/issue-next.ps1 [-Number N]
#
# Output fields: action, number, title, runner, target, model, reason, merge, merge_reason, pr,
#                head, note.  action is one of:
#   dispatch   run the routed runner on the issue (no PR exists yet)
#   review     an open PR labelled ai-review waits for the pr-reviewer (pr is set)
#   resume-pr  an open, unlabelled PR exists for the issue: try merge-pr.ps1 / agy-gate.ps1 first
#   parked     the named issue has a PR waiting for the owner (needs-review)
#   none       nothing to do
#
# Selection without -Number: first any ai-review PR (whose issue is not agent-failed), then open
# issues written by the repo owner, minus parked ones (blocked, agent-failed, a needs-review
# PR), sorted severity:critical > high > medium > low > none, then lowest number.
# Also prunes leftover worktrees first, so cargo target slots do not leak.

param([int]$Number = 0)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')

# Best effort, under 'Continue': prune writes a stderr line for each worktree it keeps or process it
# stops, and Windows PowerShell 5.1 turns native stderr into a terminating error under 'Stop'.
$ErrorActionPreference = 'Continue'
& powershell -NoProfile -File (Join-Path $PSScriptRoot 'issue-worktree.ps1') -Prune 2>$null | Out-Null
# Warn up front when prune could not free a cargo slot: a build-needing run would end in SETUP.
$slotNote = ''
$slots = @(& powershell -NoProfile -File (Join-Path $PSScriptRoot 'issue-worktree.ps1') -Status 2>$null)
if ($slots.Count -and -not ($slots | Where-Object { $_ -match ': (free|stale)' })) {
    $slotNote = "WARNING: all $($slots.Count) cargo build slots are leased; a run that builds will stop with SETUP. Free one first (issue-worktree.ps1 -Status / -Remove)"
}
$ErrorActionPreference = 'Stop'

function Out-Result($issue, [string]$action, $pr, [string]$note) {
    $o = [ordered]@{ action = $action }
    if ($issue) {
        $r = Get-Route $issue; $m = Get-MergePolicy $issue
        $o.number = [int]$issue.number; $o.title = [string]$issue.title
        $o.runner = $r.runner; $o.target = $r.target; $o.model = $r.model; $o.reason = $r.reason
        $o.merge = $m.merge; $o.merge_reason = $m.why
        # A PR already labelled ai-review is reviewed whatever the issue labels say.
        if ($pr -and (@($pr.labels | ForEach-Object { $_.name }) -contains 'ai-review')) { $o.merge = 'review'; $o.merge_reason = 'PR labelled ai-review' }
    }
    $o.pr = if ($pr) { [int]$pr.number } else { $null }
    $o.head = if ($pr) { [string]$pr.headRefName } else { $null }
    $o.note = (@($note, $slotNote) | Where-Object { $_ }) -join '; '
    [pscustomobject]$o | ConvertTo-Json -Compress
    exit 0
}

function Get-Issue([int]$n) { (& gh issue view $n --json number,title,labels,state,author) | ConvertFrom-Json }

$prs = @(& gh pr list --state open --limit 100 --json number,headRefName,labels,url | ConvertFrom-GhJson)
function Get-IssuePr([int]$n) {
    return $prs | Where-Object { $_.headRefName -like "fix/issue-$n-*" } | Select-Object -First 1
}
function Test-PrLabel($pr, [string]$label) { return (@($pr.labels | ForEach-Object { $_.name }) -contains $label) }

if ($Number -gt 0) {
    $issue = Get-Issue $Number
    if ($issue.state -ne 'OPEN') { Out-Result $issue 'none' $null "issue #$Number is $($issue.state)" }
    $pr = Get-IssuePr $Number
    $park = @(Get-LabelNames $issue | Where-Object { $ParkLabels -contains $_ })
    $note = if ($park.Count) { "labelled $($park -join ', '); running it because it was named" } else { '' }
    if ($pr -and (Test-PrLabel $pr 'needs-review')) { Out-Result $issue 'parked' $pr 'PR awaits the owner (needs-review)' }
    if ($pr -and (Test-PrLabel $pr 'ai-review')) { Out-Result $issue 'review' $pr $note }
    if ($pr) { Out-Result $issue 'resume-pr' $pr $note }
    Out-Result $issue 'dispatch' $null $note
}

$owner = Get-RepoOwner
$issues = @(& gh issue list --state open --limit 300 --author $owner --json number,title,labels | ConvertFrom-GhJson)
$byNumber = @{}; foreach ($i in $issues) { $byNumber[[int]$i.number] = $i }

# 1. Resume a review that an earlier session did not finish.
foreach ($pr in ($prs | Where-Object { Test-PrLabel $_ 'ai-review' } | Sort-Object { [int]$_.number })) {
    if ($pr.headRefName -notmatch '^fix/issue-(\d+)-') { continue }
    $i = $byNumber[[int]$Matches[1]]
    if (-not $i) { continue }
    if ((Get-LabelNames $i) -contains 'agent-failed') { continue }
    Out-Result $i 'review' $pr 'resuming an unfinished review'
}

# 2. The top open issue.
$parked = @{}
foreach ($pr in ($prs | Where-Object { Test-PrLabel $_ 'needs-review' })) {
    if ($pr.headRefName -match '^fix/issue-(\d+)-') { $parked[[int]$Matches[1]] = $true }
}
$rank = { param($i) $l = Get-LabelNames $i
    if ($l -contains 'severity:critical') { 1 } elseif ($l -contains 'severity:high') { 2 }
    elseif ($l -contains 'severity:medium') { 3 } elseif ($l -contains 'severity:low') { 4 } else { 5 } }
$next = $issues | Where-Object {
    -not $parked.ContainsKey([int]$_.number) -and
    -not (Get-LabelNames $_ | Where-Object { $ParkLabels -contains $_ })
} | Sort-Object { & $rank $_ }, { [int]$_.number } | Select-Object -First 1

if (-not $next) { Out-Result $null 'none' $null 'no open, unparked issues' }
$pr = Get-IssuePr ([int]$next.number)
if ($pr -and (Test-PrLabel $pr 'ai-review')) { Out-Result $next 'review' $pr '' }
if ($pr) { Out-Result $next 'resume-pr' $pr 'an open PR already exists for this issue' }
Out-Result $next 'dispatch' $null ''
