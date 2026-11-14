# Step 3 of /issue: check the outcome on GitHub, park failures, clean up, print the banner.
# The dispatcher saves each agent's final report to a file and passes the paths in order
# (runner first, reviewer second). Nothing here trusts a report where GitHub can answer.
#
# Usage:  powershell -NoProfile -File .claude/scripts/issue-finish.ps1 -Number N -Runner claude
#             -Target sonnet -Report <worker.txt>[,<reviewer.txt>] [-Worktree <dir>]
#
# Outcomes:
#   DONE      issue closed by a merged PR            -> worktrees removed
#   ESCALATE  PR open with needs-review              -> worktrees removed, owner question shown
#   BLOCKED   runner said BLOCKED                     -> issue labelled blocked + comment
#   FAILED    anything else                           -> issue labelled agent-failed + comment
# FAILED/BLOCKED worktrees are kept unless their work is fully pushed (then the PR holds it).
# A Claude Code agent lock a finished agent left behind is released by issue-worktree.ps1 -Remove.
# The owner removes blocked / agent-failed to let /issue pick the issue up again.

param(
    [Parameter(Mandatory = $true)][int]$Number,
    [string]$Runner = 'claude',
    [string]$Target = '',
    [string[]]$Report = @(),
    [string]$Worktree = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')
$main = Split-Path ([IO.Path]::GetFullPath((& git -C $PSScriptRoot rev-parse --path-format=absolute --git-common-dir).Trim())) -Parent
function E([int]$cp) { [char]::ConvertFromUtf32($cp) }   # emoji without non-ASCII source bytes

# --- parse the reports: last value of each KEY wins (reviewer after runner) ---
$Report = @($Report | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ })   # -File passes "a","b" as one string
$f = @{}; $worktrees = New-Object System.Collections.Generic.List[string]
$reportText = ''
foreach ($r in $Report) {
    if (-not $r -or -not (Test-Path -LiteralPath $r)) { continue }
    $text = [IO.File]::ReadAllText($r)
    $reportText += $text.Trim() + "`n`n"
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^\s*(STATUS|VERDICT|PR|WORKTREE|FILED|SKILLS|NOT TESTED|QUESTION|SUMMARY|FIXED)\s*:\s*(.*)$') {
            $k = $Matches[1]; $v = $Matches[2].Trim()
            if ($k -eq 'WORKTREE' -and $v) { $worktrees.Add($v) }
            elseif ($k -eq 'FILED' -and $f[$k] -and $v -and $v -ne 'none') { $f[$k] = "$($f[$k]),$v" }
            elseif ($k -ne 'FILED' -or -not $f[$k] -or $f[$k] -eq 'none') { $f[$k] = $v }
        }
    }
}
if ($Worktree) { $worktrees.Add($Worktree) }
$status = if ($f['VERDICT']) { $f['VERDICT'] } elseif ($f['STATUS']) { $f['STATUS'] } else { 'FAILED' }
$status = ($status -split '[\s|]')[0].ToUpper()

# --- what GitHub says ---
$issue = (& gh issue view $Number --json number,title,state,closedByPullRequestsReferences) | ConvertFrom-Json
$prNum = $null
if ($f['PR'] -match '/pull/(\d+)') { $prNum = [int]$Matches[1] }
if (-not $prNum) {
    $hit = @(& gh pr list --state all --limit 200 --json number,headRefName | ConvertFrom-GhJson |
        Where-Object { $_.headRefName -like "fix/issue-$Number-*" } | Sort-Object { -[int]$_.number })
    $prNum = if ($hit.Count) { [int]$hit[0].number } else { $null }
}
$pr = if ($prNum) { (& gh pr view $prNum --json number,state,url,labels,headRefName) | ConvertFrom-Json } else { $null }
$prLabels = if ($pr) { @($pr.labels | ForEach-Object { $_.name }) } else { @() }

$outcome =
    if ($issue.state -eq 'CLOSED' -and ((@($issue.closedByPullRequestsReferences).Count -gt 0) -or ($pr -and $pr.state -eq 'MERGED'))) { 'DONE' }
    elseif ($pr -and $pr.state -eq 'OPEN' -and $prLabels -contains 'needs-review') { 'ESCALATE' }
    elseif ($status -eq 'BLOCKED') { 'BLOCKED' }
    else { 'FAILED' }

# --- park a non-success so the next /issue moves on ---
if ($outcome -eq 'BLOCKED' -or $outcome -eq 'FAILED') {
    $label = if ($outcome -eq 'BLOCKED') { 'blocked' } else { 'agent-failed' }
    $why = if ($f['QUESTION'] -and $f['QUESTION'] -ne 'none') { $f['QUESTION'] } elseif ($f['SUMMARY']) { $f['SUMMARY'] } else { 'the runner returned no report' }
    $body = Write-BodyFile ("**/issue run $($outcome.ToLower())** ($Runner/$Target, status ``$status``).`n`n$why`n`n" +
        "Remove the ``$label`` label to let ``/issue`` pick this issue up again.")
    & gh issue edit $Number --add-label $label | Out-Null
    & gh issue comment $Number --body-file $body | Out-Null
    Remove-Item $body -ErrorAction SilentlyContinue
}

# --- worktrees ---
$removed = @(); $kept = @()
foreach ($wt in ($worktrees | Select-Object -Unique)) {
    if (-not (Test-Path -LiteralPath $wt)) { continue }
    $pushed = $false
    if ($outcome -ne 'DONE' -and $outcome -ne 'ESCALATE') {
        $dirty = @(& git --no-optional-locks -C $wt status --porcelain 2>$null | Where-Object { $_ -notmatch '^\?\? (src/node_modules|src-tauri/target)' })
        $unpushed = @(& git -C $wt log HEAD --not --remotes --oneline 2>$null)
        $pushed = ($dirty.Count -eq 0 -and $unpushed.Count -eq 0)
    }
    if ($outcome -eq 'DONE' -or $outcome -eq 'ESCALATE' -or $pushed) {
        # 'Continue' so a stderr line from the child is a kept worktree in the banner, not a crash
        # before it (Windows PowerShell 5.1 turns native stderr into a terminating error under Stop).
        $ErrorActionPreference = 'Continue'
        & powershell -NoProfile -File (Join-Path $PSScriptRoot 'issue-worktree.ps1') -Remove -Path $wt 2>$null | Out-Null
        $ok = ($LASTEXITCODE -eq 0)
        $ErrorActionPreference = 'Stop'
        if ($ok) { $removed += $wt } else { $kept += $wt }
    } else { $kept += $wt }
}
foreach ($b in @(& git -C $main branch --list "fix/issue-$Number-*" "review/issue-$Number*" --format '%(refname:short)')) {
    if ($b) { & git -C $main branch -D $b 2>$null | Out-Null }
}

# --- main checkout: fast-forward only when it is on main ---
$cur = (& git -C $main rev-parse --abbrev-ref HEAD).Trim()
& git -C $main fetch --quiet origin main 2>$null
$mainNote = if ($cur -ne 'main') { "not updated: main checkout is on $cur" } else {
    & git -C $main merge --ff-only --quiet origin/main 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { 'fast-forwarded' } else { 'not updated: local changes overlap incoming files' } }

# --- filed issues: show their live route ---
$filed = @(([string]$f['FILED']) -split '[,\s#]+' | Where-Object { $_ -match '^\d+$' } | Select-Object -Unique)
$filedText = if ($filed.Count -eq 0) { 'none' } else {
    ($filed | ForEach-Object {
        $j = (& powershell -NoProfile -File (Join-Path $PSScriptRoot 'route-issue.ps1') -Number $_) | ConvertFrom-Json
        if ($j) { "#$_ -> $($j.runner)/$($j.target), $($j.merge)" } else { "#$_" } }) -join '; ' }

# --- banner ---
$t = $issue.title
$bar = '=' * 70
$url = if ($pr) { $pr.url } else { 'none' }
$reviewed = ($f['VERDICT'] -and $outcome -eq 'DONE')
$lines = @($bar)
switch ($outcome) {
    'DONE' {
        $lines += "$(E 0x2705) COMPLETED: Issue #$Number (""$t"") resolved by $Runner/$Target, PR merged$(if ($reviewed) { ', reviewed and verified by claude/opus' })."
        $lines += "$(E 0x1F517) PR: $url"
        if ($reviewed) { $lines += "$(E 0x1F50E) Not tested: $(if ($f['NOT TESTED']) { $f['NOT TESTED'] } else { 'none' })" }
    }
    'ESCALATE' {
        $lines += "$(E 0x2753) YOUR DECISION NEEDED: Issue #$Number (""$t"") by $Runner/$Target, PR open."
        $lines += "$(E 0x1F517) PR: $url"
        $lines += "$(E 0x1F5E3)$(E 0xFE0F) $($f['QUESTION'])"
        $lines += "$(E 0x1F449) Reply here with your answer, or merge as is: gh pr merge $($pr.number) --squash --delete-branch"
    }
    default {
        $lines += "$(E 0x26A0)$(E 0xFE0F) Issue #$Number (""$t"") was not completed by $Runner/${Target}: $outcome, labelled $(if ($outcome -eq 'BLOCKED') { 'blocked' } else { 'agent-failed' })."
        $lines += "$(E 0x1F517) PR: $url"
        $lines += ''
        $lines += $reportText.TrimEnd()
        $lines += ''
    }
}
$lines += "$(E 0x1F195) Filed: $filedText"
if ($f['SKILLS'] -and $f['SKILLS'] -ne 'none') { $lines += "$(E 0x1F9E9) Skill suggestion: $($f['SKILLS']) (run /find-skills yourself if you want it)" }
$lines += "$(E 0x1F9F9) Worktrees removed: $($removed.Count)$(if ($kept.Count) { "; kept: $($kept -join ', ')" }); main $mainNote"
if ($outcome -eq 'DONE') { $lines += "$(E 0x1F9EA) Try it: powershell -NoProfile -File .claude/scripts/install-main.ps1 -CloseApp -Launch" }
if ($outcome -eq 'ESCALATE') { $lines += "$(E 0x1F9EA) Try it: powershell -NoProfile -File .claude/scripts/install-main.ps1 -Ref origin/$($pr.headRefName) -CloseApp -Launch" }
$lines += "$(E 0x1F4A1) ACTION REQUIRED: Type ``/clear`` now to wipe context tokens before running ``/issue`` again!"
$lines += $bar
$lines | ForEach-Object { Write-Output $_ }
exit 0
