# Merge gate for AGY (Gemini) pull requests. AGY opens PRs but never merges them; the /issue
# dispatcher runs this, and only this decides whether an AGY change reaches main.
#
# AGY is routed prose-only work (docs, specs). The gate enforces that structurally instead of
# asking a model to review the diff: every changed path (both names of a rename) must be a
# Markdown file outside the tool/policy areas below.
#   Rejected -> the PR is closed with a comment and the issue gets the label route:claude, so the
#               next /issue routes it to Claude automatically. Exit 3.
#   Allowed + -Review, or the diff touches a sensitive doc (docs/spec, docs/FORMAT.md,
#   docs/testing; see Policy.ps1) -> labelled ai-review for the pr-reviewer. Exit 4.
#   Allowed otherwise -> merge-pr.ps1 waits for CI and merges. Its exit code is returned.
#
# Usage:  powershell -NoProfile -File .claude/scripts/agy-gate.ps1 -Pr <number> [-Review]
# Exit:   0 merged, 3 rejected, 4 needs review, 5 CI failed, 6 conflict, 1 error.

param(
    [Parameter(Mandatory = $true)][int]$Pr,
    [switch]$Review
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')

$Blocked = @('.claude/', '.agents/', '.github/', '.cargo/')
$BlockedFiles = @('CLAUDE.md', 'GEMINI.md', 'AGENTS.md', 'SECURITY.md')

function Test-Allowed([string]$p) {
    $p = $p.Replace('\', '/')
    if (-not $p.EndsWith('.md', [StringComparison]::OrdinalIgnoreCase)) { return $false }
    foreach ($b in $Blocked) { if ($p.StartsWith($b, [StringComparison]::OrdinalIgnoreCase)) { return $false } }
    if ($BlockedFiles -contains (Split-Path $p -Leaf)) { return $false }
    return $true
}

$pull = (& gh pr view $Pr --json number,state,baseRefName,headRefName,url) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { Write-Output "ERROR: cannot load PR $Pr"; exit 1 }
if ($pull.state -ne 'OPEN') { Write-Output "ERROR: PR #$Pr is $($pull.state), not OPEN"; exit 1 }
if ($pull.baseRefName -ne 'main') { Write-Output "ERROR: PR #$Pr targets $($pull.baseRefName), not main"; exit 1 }

$paths = Get-PrPaths $Pr
if ($paths.Count -eq 0) { Write-Output "REJECTED #${Pr}: changes no files"; exit 3 }
$bad = @($paths | Where-Object { -not (Test-Allowed $_) })

if ($bad.Count -gt 0) {
    $list = ($bad | ForEach-Object { "- ``$_``" }) -join "`n"
    $body = Write-BodyFile "AGY gate: rejected. AGY may only change Markdown docs, and this PR also touches:`n`n$list`n`nClosed. The issue is now labelled ``route:claude``, so the next ``/issue`` hands it to Claude."
    & gh pr comment $Pr --body-file $body | Out-Null
    & gh pr close $Pr | Out-Null
    Remove-Item $body -ErrorAction SilentlyContinue
    if ($pull.headRefName -match 'issue-(\d+)') { & gh issue edit $Matches[1] --add-label 'route:claude' | Out-Null }
    Write-Output "REJECTED #${Pr}: $($bad -join ', ')"
    exit 3
}

$sensitive = Get-SensitivePaths $paths
if ($Review -or $sensitive.Count -gt 0) {
    & gh pr edit $Pr --add-label ai-review | Out-Null
    Write-Output "REVIEW #${Pr}: $(if ($sensitive.Count) { 'sensitive docs: ' + ($sensitive -join ', ') } else { 'issue merge policy is review' })"
    exit 4
}

& powershell -NoProfile -File (Join-Path $PSScriptRoot 'merge-pr.ps1') -Pr $Pr
exit $LASTEXITCODE
