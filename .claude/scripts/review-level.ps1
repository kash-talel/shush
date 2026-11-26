# The level the pr-reviewer runs `/code-review` at for one PR. Decided by script, never by judgment;
# the rule itself is Policy.ps1 Get-ReviewLevel. `high` unless ALL of these hold:
#   - not high-risk (Policy.ps1 Get-HighRiskReason over EVERY linked issue and every changed path);
#   - the Gemini first pass posted a result for this exact PR head (it did not fail or time out);
#   - the scorecard says DROP (hydrogen-stats.ps1 -Decision, re-evaluated on every call, so one
#     counter-example switches every later review back to high);
#   - this PR is not a random 1-in-4 spot check, which keeps measuring what only `high` finds.
# A PR with no linked issue, any error, missing data or unexpected output -> high.
#
# Usage:  powershell -NoProfile -File .claude/scripts/review-level.ps1 -Pr <number> [-Issue <number>]
#         -Issue: the issue the dispatcher named; checked together with the PR's own references.
# Output: one line, `LEVEL: high|medium (<reason>)`. Exit 0.

param([Parameter(Mandatory = $true)][int]$Pr, [int]$Issue = 0)

trap { Write-Output "LEVEL: high (could not decide: $($_.Exception.Message))"; exit 0 }
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')
$trusted = @('OWNER', 'MEMBER', 'COLLABORATOR')   # public repo: only their comments count

$p = (& gh pr view $Pr --json title,headRefOid,closingIssuesReferences) | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $p -or -not $p.headRefOid) { throw "cannot read PR $Pr" }

# Every issue the PR is tied to: the dispatcher's, all closing references, every #N in the title.
# More references can only add checks, never remove one.
$nums = @()
if ($Issue -gt 0) { $nums += $Issue }
$nums += @($p.closingIssuesReferences | ForEach-Object { [int]$_.number })
$nums += @([regex]::Matches([string]$p.title, '#(\d+)') | ForEach-Object { [int]$_.Groups[1].Value })
$nums = @($nums | Where-Object { $_ -gt 0 -and $_ -ne $Pr } | Select-Object -Unique)
if ($nums.Count -eq 0) { Write-Output 'LEVEL: high (no linked issue to check)'; exit 0 }
$issues = @(foreach ($n in $nums) {
    # The issues endpoint also answers for a PR number, so a #N that is a PR is checked too.
    $i = (& gh api "repos/{owner}/{repo}/issues/$n") | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $i) { throw "cannot read issue #$n" }
    $i
})
$risk = Get-HighRiskReason $issues (Get-PrPaths $Pr)

$oid = [string]$p.headRefOid
$fp = @(& gh api "repos/{owner}/{repo}/issues/$Pr/comments" --paginate --jq '.[] | @json' |
    Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object { ($trusted -contains [string]$_.author_association) -and
        ([string]$_.body -match "^\W?<!-- hydrogen-review head=$oid result=(clean|findings) -->") })
if ($LASTEXITCODE -ne 0) { throw 'cannot read PR comments' }

$score = 'not run'
if (-not $risk -and $fp.Count -gt 0) {
    $d = @(& powershell -NoProfile -File (Join-Path $PSScriptRoot 'hydrogen-stats.ps1') -Decision)
    if ($LASTEXITCODE -ne 0 -or $d.Count -eq 0) { throw 'scorecard failed' }
    $score = ([string]$d[-1]).Trim()
}
Write-Output "LEVEL: $(Get-ReviewLevel $risk ($fp.Count -gt 0) $score (Get-Random -Maximum $ReviewSpotCheckOneIn))"
exit 0
