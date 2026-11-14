# Route an issue: which runner and model, and whether its PR needs review.
# Computed live from the issue's labels and title on every call (see Policy.ps1); nothing is
# stored, so there is no routing file to keep in sync and no chore commits.
#
# Usage:  powershell -NoProfile -File .claude/scripts/route-issue.ps1 -Number 42
#         powershell -NoProfile -File .claude/scripts/route-issue.ps1 -List      (table of open issues)
# Output: -Number: one JSON line {"number","title","model","runner","target","reason","merge","merge_reason"}
#         If the issue cannot be read, merge fails closed to review and the exit code is 1.

param(
    [int]$Number = 0,
    [switch]$List
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')

function Format-Route($issue) {
    $r = Get-Route $issue
    $m = Get-MergePolicy $issue
    return [pscustomobject][ordered]@{
        number = [int]$issue.number; title = [string]$issue.title
        model = $r.model; runner = $r.runner; target = $r.target; reason = $r.reason
        merge = $m.merge; merge_reason = $m.why
    }
}

if ($List) {
    $issues = @(& gh issue list --state open --limit 300 --json number,title,labels | ConvertFrom-GhJson)
    $rank = { param($i) $l = Get-LabelNames $i
        if ($l -contains 'severity:critical') { 1 } elseif ($l -contains 'severity:high') { 2 }
        elseif ($l -contains 'severity:medium') { 3 } elseif ($l -contains 'severity:low') { 4 } else { 5 } }
    $rows = $issues | Sort-Object { & $rank $_ }, { [int]$_.number }
    Write-Output '| # | Title | Runner / model | Merge | Parked |'
    Write-Output '|---|---|---|---|---|'
    $count = @{}
    foreach ($i in $rows) {
        $x = Format-Route $i
        $t = if ($x.title.Length -gt 70) { $x.title.Substring(0, 67) + '...' } else { $x.title }
        $park = @(Get-LabelNames $i | Where-Object { $ParkLabels -contains $_ }) -join ','
        Write-Output ("| {0} | {1} | {2} / {3} | {4} | {5} |" -f $x.number, $t.Replace('|', '/'), $x.runner, $x.target, $x.merge, $park)
        $count[$x.target] = 1 + [int]$count[$x.target]
    }
    Write-Output ''
    Write-Output (($count.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name): $($_.Value)" }) -join ', ')
    exit 0
}

if ($Number -le 0) { throw 'use -Number N or -List' }
$raw = & gh issue view $Number --json number,title,labels
if ($LASTEXITCODE -ne 0) {
    [Console]::Error.WriteLine("route-issue: gh could not load issue #$Number")
    exit 1
}
Format-Route ($raw | ConvertFrom-Json) | ConvertTo-Json -Compress
exit 0
