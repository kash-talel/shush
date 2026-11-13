# Merge gate for AGY (Gemini) pull requests. AGY opens PRs but never merges them; the /issue
# dispatcher runs this, and only this decides whether an AGY change reaches main.
#
# AGY is routed prose-only work (docs, specs). The gate enforces that structurally instead of
# asking a model to review the diff: every changed path must be a Markdown file outside the
# tool/policy areas below. Anything else (code, tests, scripts, assets, config) is rejected
# and the PR is left open with a comment, for Claude or the owner to take over.
#
# Usage:  powershell -NoProfile -File .claude/scripts/agy-gate.ps1 -Pr <number|url> [-Merge]
# Exit:   0 = allowed (and merged when -Merge), 3 = rejected, 1 = error.

param(
    [Parameter(Mandatory = $true)][string]$Pr,
    [switch]$Merge
)

$ErrorActionPreference = 'Stop'

# Markdown under these prefixes is still off-limits: agent instructions, CI, and policy files
# change how the pipeline itself behaves.
$Blocked = @('.claude/', '.agents/', '.github/', '.cargo/')
$BlockedFiles = @('CLAUDE.md', 'GEMINI.md', 'AGENTS.md', 'SECURITY.md')

function Test-Allowed([string]$p) {
    $p = $p.Replace('\', '/')
    if (-not $p.EndsWith('.md', [StringComparison]::OrdinalIgnoreCase)) { return $false }
    foreach ($b in $Blocked) { if ($p.StartsWith($b, [StringComparison]::OrdinalIgnoreCase)) { return $false } }
    if ($BlockedFiles -contains (Split-Path $p -Leaf)) { return $false }
    return $true
}

$raw = & gh pr view $Pr --json number,state,baseRefName,headRefName,files,url
if ($LASTEXITCODE -ne 0) { [Console]::Error.WriteLine("agy-gate: cannot load PR $Pr"); exit 1 }
$pull = $raw | ConvertFrom-Json

if ($pull.state -ne 'OPEN') { [Console]::Error.WriteLine("agy-gate: PR #$($pull.number) is $($pull.state), not OPEN"); exit 1 }
if ($pull.baseRefName -ne 'main') { [Console]::Error.WriteLine("agy-gate: PR #$($pull.number) targets $($pull.baseRefName), not main"); exit 1 }

$paths = @($pull.files | ForEach-Object { [string]$_.path })
if ($paths.Count -eq 0) { [Console]::Error.WriteLine("agy-gate: PR #$($pull.number) changes no files"); exit 3 }
$bad = @($paths | Where-Object { -not (Test-Allowed $_) })

if ($bad.Count -gt 0) {
    $list = ($bad | ForEach-Object { "- ``$_``" }) -join "`n"
    $body = "AGY gate: rejected. AGY may only change Markdown docs, and this PR also touches:`n`n$list`n`nLeft open. If the issue needs code, set its entry in ``.claude/issue-routing.json`` to runner ``claude`` and run ``/issue`` again."
    & gh pr comment $pull.number --body $body | Out-Null
    Write-Output "REJECTED #$($pull.number): $($bad -join ', ')"
    exit 3
}

if (-not $Merge) { Write-Output "ALLOWED #$($pull.number): $($paths.Count) doc file(s)"; exit 0 }

& gh pr merge $pull.number --squash --admin
if ($LASTEXITCODE -ne 0) { [Console]::Error.WriteLine("agy-gate: merge failed for PR #$($pull.number) (conflict? rebase the branch and re-run)"); exit 1 }
& git push origin --delete $pull.headRefName 2>$null | Out-Null
Write-Output "MERGED #$($pull.number) ($($pull.url))"
exit 0
