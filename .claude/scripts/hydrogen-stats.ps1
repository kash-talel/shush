# Scorecard for the Gemini first pass (hydrogen-review.ps1) and the decision it feeds:
# may the pr-reviewer's `/code-review high` drop to `medium`?
#
# All data lives on GitHub, posted by maintainers' accounts only (the repo is public):
#   <!-- hydrogen-review head=<sha> result=clean|findings -->      first-pass comment (hydrogen-review.ps1)
#   <!-- review-score v1 confirmed=.. cr=.. hy=.. own=.. cr_only=.. cr_only_mh=.. hy_only=..
#        hy_leads=.. hy_rejected=.. hy_missed_high=.. -->              pr-reviewer comment (pr-reviewer.md Step 5)
#   "Introduced by #<PR>" in an issue body                          a bug traced back to an earlier PR
#
# Decision rule, fixed in advance (2026-11-26) so it cannot drift with the data:
#   DROP to medium only if ALL hold:
#     1. at least 15 reviewed PRs carry a review-score, with at least 20 confirmed defects in total;
#     2. in the last 15 of them, `/code-review high` found no medium/high defect that neither the first
#        pass nor the reviewer's own checks found (sum of cr_only_mh = 0);
#     3. no severity:high/critical bug was traced ("Introduced by") to a PR the first pass called clean
#        and that merged without an Opus review.
#   Otherwise KEEP high. After a drop, keep collecting: one cr_only_mh > 0 in a later
#   `/code-review high` spot check, or one rule-3 escape, means go back to high.
#
# Usage:  powershell -NoProfile -File .claude/scripts/hydrogen-stats.ps1 [-Window 15]

param([int]$Window = 15)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')
$trusted = @('OWNER', 'MEMBER', 'COLLABORATOR')

function PrOf([string]$url) { if ($url -match '/(?:issues|pull)/(\d+)$') { [int]$Matches[1] } }

$comments = @(& gh api 'repos/{owner}/{repo}/issues/comments?per_page=100&sort=created&direction=asc' --paginate `
    --jq '.[] | select(.body | test(\"<!-- (hydrogen-review|review-score) |^.?## AI review\")) | {u: .issue_url, a: .author_association, b: .body, t: .created_at} | @json' |
    Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $trusted -contains [string]$_.a })
if ($LASTEXITCODE -ne 0) { throw 'cannot read PR comments' }
# PRs an Opus pr-reviewer looked at, with or without a score (older reviews have none).
$opus = @{}
foreach ($c in $comments) { if ($c.b -match '^.?## AI review') { $opus[(PrOf $c.u)] = $true } }

# --- first pass: last result per PR ---
$fp = @{}
foreach ($c in $comments) {
    if ($c.b -match '<!-- hydrogen-review head=\w+ result=(clean|findings) -->') { $fp[(PrOf $c.u)] = $Matches[1] }
}
# --- reviewer scores: last score per PR, in time order ---
$scores = [ordered]@{}
foreach ($c in $comments) {
    if ($c.b -match '<!-- review-score v1 ([^>]*?)\s*-->') {
        $row = @{ pr = (PrOf $c.u) }
        foreach ($kv in ($Matches[1] -split '\s+')) { $k, $v = $kv -split '=', 2; if ($v -match '^\d+$') { $row[$k] = [int]$v } }
        $scores[[string]$row.pr] = $row
    }
}
$rows = @($scores.Values)
function Sum($set, [string]$k) { $s = 0; foreach ($r in $set) { if ($r.ContainsKey($k)) { $s += $r[$k] } }; $s }

# --- escapes: bugs traced to a PR that merged on a clean first pass without an Opus review ---
$escapes = @()
$traced = @(& gh issue list --state all --limit 500 --search 'Introduced in:body' --json number,title,body,labels |
    ConvertFrom-GhJson)
if ($LASTEXITCODE -ne 0) { throw 'cannot search issues' }
foreach ($i in $traced) {
    foreach ($m in [regex]::Matches([string]$i.body, 'Introduced by #(\d+)')) {
        $src = [int]$m.Groups[1].Value
        if ($fp[$src] -eq 'clean' -and -not $opus[$src]) {
            $sev = @($i.labels | ForEach-Object { $_.name } | Where-Object { $_ -like 'severity:*' }) -join ','
            $escapes += [pscustomobject]@{ issue = $i.number; pr = $src; sev = $sev }
        }
    }
}

# --- scorecard ---
$all = $rows
$last = @($rows | Select-Object -Last $Window)
$D = Sum $all 'confirmed'; $H = Sum $all 'hy'; $L = Sum $all 'hy_leads'; $J = Sum $all 'hy_rejected'
$pct = { param($a, $b) if ($b -gt 0) { '{0:P0}' -f ($a / $b) } else { 'n/a' } }
$routine = @($fp.Keys | Where-Object { -not $opus[$_] })
Write-Output "First pass ran on $($fp.Count) PRs: $(@($fp.Values | Where-Object { $_ -eq 'clean' }).Count) clean, $(@($fp.Values | Where-Object { $_ -eq 'findings' }).Count) with findings; $($routine.Count) without an Opus review."
Write-Output "Opus-reviewed PRs with a score: $($all.Count); confirmed defects: $D"
Write-Output "  Hydrogen recall (share of confirmed defects it reported): $(& $pct $H $D)   precision (leads not rejected): $(& $pct ($L - $J) $L) of $L leads"
Write-Output "  found only by /code-review: $(Sum $all 'cr_only') (medium/high: $(Sum $all 'cr_only_mh')); only by Hydrogen: $(Sum $all 'hy_only'); high defects Hydrogen missed: $(Sum $all 'hy_missed_high')"
Write-Output "  last $($last.Count): /code-review-only medium/high defects: $(Sum $last 'cr_only_mh')"
Write-Output "Escapes after a clean first pass (no Opus review): $($escapes.Count)$(if ($escapes.Count) { ': ' + (($escapes | ForEach-Object { "#$($_.issue) from PR #$($_.pr) [$($_.sev)]" }) -join '; ') })"

$why = @()
if ($all.Count -lt 15 -or $D -lt 20) { $why += "need >= 15 scored PRs and >= 20 defects (have $($all.Count), $D)" }
if ((Sum $last 'cr_only_mh') -gt 0) { $why += "/code-review high found $(Sum $last 'cr_only_mh') medium/high defect(s) nobody else did in the last $($last.Count)" }
$highEsc = @($escapes | Where-Object { $_.sev -match 'high|critical' })
if ($highEsc.Count -gt 0) { $why += "$($highEsc.Count) high/critical bug(s) escaped a clean first pass" }
if ($why.Count -eq 0) { Write-Output 'DECISION: DROP /code-review to medium in pr-reviewer.md (rule met). Keep collecting; revert on the first counter-example.' }
else { Write-Output "DECISION: KEEP /code-review high: $($why -join '; ')" }
