# The ONLY way an /issue runner merges a PR. Agents never call `gh pr merge` themselves.
#
#  1. Unless -Reviewed: a PR labelled ai-review/needs-review, or whose diff touches a sensitive
#     path (Policy.ps1), is NOT merged: it gets the ai-review label and exit 4.
#  2. Waits for the REQUIRED CI checks on GitHub (clean machine, not the agent's warm build).
#     A failed "Windows · Rust + Svelte" run is re-run once (flaky tests); a second failure is final.
#  3. Squash-merges without --admin, so the branch ruleset is honoured.
#
# Usage:  powershell -NoProfile -File .claude/scripts/merge-pr.ps1 -Pr <number> [-Reviewed]
#         -Reviewed: only the pr-reviewer agent passes this, after its APPROVE verdict.
# Exit:   0 merged (or already merged)   4 needs review (labelled ai-review, not merged)
#         5 CI failed or timed out       6 conflicts with main (rebase, verify, push, rerun)
#         1 other error
# Output is a few lines on purpose: CI polling never reaches the agent's context.

param(
    [Parameter(Mandatory = $true)][int]$Pr,
    [switch]$Reviewed,
    [int]$TimeoutMinutes = 30
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')

function View { (& gh pr view $Pr --json number,state,url,headRefName,labels,mergeable) | ConvertFrom-Json }

$p = View
if ($p.state -eq 'MERGED') { Write-Output "MERGED #$Pr already ($($p.url))"; exit 0 }
if ($p.state -ne 'OPEN') { Write-Output "ERROR #${Pr} is $($p.state)"; exit 1 }

if (-not $Reviewed) {
    $labels = @($p.labels | ForEach-Object { $_.name })
    if ($labels -contains 'needs-review') { Write-Output "REVIEW #${Pr}: waits for the owner (needs-review)"; exit 4 }
    if ($labels -contains 'ai-review') { Write-Output "REVIEW #${Pr}: labelled ai-review; the pr-reviewer merges it"; exit 4 }
    $hits = Get-SensitivePaths (Get-PrPaths $Pr)
    if ($hits.Count -gt 0) {
        & gh pr edit $Pr --add-label ai-review | Out-Null
        Write-Output "REVIEW #${Pr}: touches sensitive paths, labelled ai-review: $($hits -join ', ')"
        exit 4
    }
}

if ($p.mergeable -eq 'CONFLICTING') { Write-Output "CONFLICT #${Pr}: conflicts with main"; exit 6 }

# --- wait for required checks, quietly ---
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$start = Get-Date
$rerun = $false
while ($true) {
    $json = & gh pr checks $Pr --required --json name,bucket,link 2>$null
    $checks = @()
    if ($json) { try { $checks = @($json | ConvertFrom-Json) } catch { $checks = @() } }
    $pending = @($checks | Where-Object { $_.bucket -eq 'pending' })
    $failed = @($checks | Where-Object { $_.bucket -eq 'fail' -or $_.bucket -eq 'cancel' })

    if ($checks.Count -gt 0 -and $pending.Count -eq 0) {
        if ($failed.Count -eq 0) { break }
        # -like, not the literal name: this file has no BOM, so PowerShell 5.1 misreads a non-ASCII '·'.
        $ci = $failed | Where-Object { $_.name -like 'Windows*Rust*Svelte' } | Select-Object -First 1
        if (-not $rerun -and $ci -and ($failed.Count -eq 1) -and ([string]$ci.link -match '/runs/(\d+)')) {
            & gh run rerun $Matches[1] --failed 2>$null | Out-Null
            $rerun = $true
            Start-Sleep -Seconds 30
            continue
        }
        Write-Output "CI FAILED #${Pr}: $(($failed | ForEach-Object { $_.name }) -join ', ')$(if ($rerun) { ' (also after one re-run)' })"
        foreach ($f in $failed) {
            if ([string]$f.link -match '/runs/(\d+)') { Write-Output "  see: gh run view $($Matches[1]) --log-failed" }
        }
        exit 5
    }
    if ($checks.Count -eq 0 -and ((Get-Date) - $start).TotalMinutes -gt 5) {
        Write-Output "CI FAILED #${Pr}: no required checks reported after 5 minutes"; exit 5
    }
    if ((Get-Date) -gt $deadline) { Write-Output "CI FAILED #${Pr}: checks still pending after $TimeoutMinutes minutes"; exit 5 }
    Start-Sleep -Seconds 20
}

# --- merge (no --admin: the ruleset's required checks are green now) ---
$err = & gh pr merge $Pr --squash 2>&1
if ($LASTEXITCODE -ne 0) {
    $p = View
    if ($p.state -eq 'MERGED') { Write-Output "MERGED #$Pr ($($p.url))"; exit 0 }
    if ($p.mergeable -eq 'CONFLICTING') { Write-Output "CONFLICT #${Pr}: main moved and the PR now conflicts"; exit 6 }
    Write-Output "ERROR #${Pr}: merge failed: $(($err | Out-String).Trim())"
    exit 1
}
& gh api -X DELETE "repos/{owner}/{repo}/git/refs/heads/$($p.headRefName)" 2>$null | Out-Null   # usually auto-deleted already
if ($Reviewed) { & gh pr edit $Pr --remove-label ai-review 2>$null | Out-Null }
Write-Output "MERGED #$Pr ($($p.url))$(if ($rerun) { ' after one CI re-run' })"
exit 0
