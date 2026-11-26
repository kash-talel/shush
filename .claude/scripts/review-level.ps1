# The level the pr-reviewer runs `/code-review` at for one PR. Decided by script, never by judgment:
#   high    high-risk work (Policy.ps1 Get-HighRiskReason: severity high/critical, crypto, file
#           format, sync, memory hygiene, or crypto/vault/updater/bridge paths): ALWAYS, whatever
#           the scorecard says
#   high    the scorecard says KEEP (hydrogen-stats.ps1 -Decision, re-evaluated on every call, so
#           one counter-example switches every later review back to high)
#   high    spot check: 1 in 4 eligible PRs even after a DROP, so the scorecard keeps measuring
#           what only `/code-review high` finds
#   medium  everything else, only after a DROP
# Any error, missing data or unexpected output -> high.
#
# Usage:  powershell -NoProfile -File .claude/scripts/review-level.ps1 -Pr <number>
# Output: one line, `LEVEL: high|medium (<reason>)`. Exit 0.

param([Parameter(Mandatory = $true)][int]$Pr)

trap { Write-Output "LEVEL: high (could not decide: $($_.Exception.Message))"; exit 0 }
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')

$p = (& gh pr view $Pr --json title,closingIssuesReferences) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $p) { throw "cannot read PR $Pr" }
$issueNo = $null
$refs = @($p.closingIssuesReferences)
if ($refs.Count -gt 0) { $issueNo = [int]$refs[0].number } elseif ([string]$p.title -match '#(\d+)') { $issueNo = [int]$Matches[1] }
$issue = $null
if ($issueNo) {
    $issue = (& gh issue view $issueNo --json title,labels) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw "cannot read issue #$issueNo" }
}
$risk = Get-HighRiskReason $issue (Get-PrPaths $Pr)
if ($risk) { Write-Output "LEVEL: high (high-risk: $risk; never lowered)"; exit 0 }

$d = @(& powershell -NoProfile -File (Join-Path $PSScriptRoot 'hydrogen-stats.ps1') -Decision)
if ($LASTEXITCODE -ne 0 -or $d.Count -eq 0) { throw 'scorecard failed' }
$d = ([string]$d[-1]).Trim()
if ($d -ne 'DROP') { Write-Output "LEVEL: high (scorecard $d)"; exit 0 }
if ($Pr % 4 -eq 0) { Write-Output 'LEVEL: high (spot check, 1 in 4 after a DROP)'; exit 0 }
Write-Output 'LEVEL: medium (scorecard DROP; not high-risk)'
exit 0
