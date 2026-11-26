# The ONLY way an /issue runner merges a PR. Agents never call `gh pr merge` themselves.
#
#  1. Unless -Reviewed: a PR labelled ai-review/needs-review, or whose diff touches a sensitive
#     path (Policy.ps1), is NOT merged: it gets the ai-review label and exit 4.
#     Otherwise the Gemini first pass (hydrogen-review.ps1) runs beside the CI wait; any finding
#     labels the PR ai-review and exits 4 instead of merging. If Hydrogen is unavailable the merge
#     goes ahead as before (the output says so).
#  2. Waits for the REQUIRED CI checks on GitHub (clean machine, not the agent's warm build).
#     A failed "Windows · Rust + Svelte" run is re-run once (flaky tests); a second failure is final.
#  3. Squash-merges without --admin, so the branch ruleset is honoured.
#
# Usage:  powershell -NoProfile -File .claude/scripts/merge-pr.ps1 -Pr <number> [-Reviewed]
#         -Reviewed: only the pr-reviewer agent passes this, after its APPROVE verdict.
# Exit:   0 merged (or already merged)   4 needs review (labelled ai-review, not merged: sensitive
#         paths or a first-pass finding)
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

# --- first pass by a second model family, in parallel with CI (routine PRs only) ---
$fp = $null
if (-not $Reviewed) {
    $fpOut = [IO.Path]::Combine([IO.Path]::GetTempPath(), "shush-firstpass-$Pr-$([guid]::NewGuid().ToString('N').Substring(0,8)).txt")
    $fpArgs = "-NoProfile -File `"$(Join-Path $PSScriptRoot 'hydrogen-review.ps1')`" -Pr $Pr"
    $fp = Start-Process -FilePath 'powershell.exe' -ArgumentList $fpArgs -RedirectStandardOutput $fpOut `
        -RedirectStandardError "$fpOut.err" -NoNewWindow -PassThru
    $null = $fp.Handle
}
function Stop-FirstPass {
    # try/catch: under 'Stop', PowerShell 5.1 turns taskkill's stderr (process already gone) into a
    # terminating error, which would turn exit 5 into exit 1.
    if ($fp -and -not $fp.HasExited) { try { & taskkill /T /F /PID $fp.Id 2>$null | Out-Null } catch { } }
    if ($fp) { Remove-Item -LiteralPath $fpOut, "$fpOut.err" -ErrorAction SilentlyContinue }
}

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
        Stop-FirstPass
        exit 5
    }
    if ($checks.Count -eq 0 -and ((Get-Date) - $start).TotalMinutes -gt 5) {
        Write-Output "CI FAILED #${Pr}: no required checks reported after 5 minutes"; Stop-FirstPass; exit 5
    }
    if ((Get-Date) -gt $deadline) { Write-Output "CI FAILED #${Pr}: checks still pending after $TimeoutMinutes minutes"; Stop-FirstPass; exit 5 }
    Start-Sleep -Seconds 20
}

# --- first-pass result: a finding stops the merge and sends the PR to the pr-reviewer ---
$fpNote = ''
if ($fp) {
    if (-not $fp.WaitForExit(35 * 60 * 1000)) { Stop-FirstPass; $fpNote = 'first pass timed out' }
    $fpLine = if (Test-Path -LiteralPath $fpOut) { ((Get-Content -LiteralPath $fpOut) -join ' ').Trim() } else { '' }
    Remove-Item -LiteralPath $fpOut, "$fpOut.err" -ErrorAction SilentlyContinue
    if (-not $fpNote) {
        if ($fp.ExitCode -eq 3) {
            & gh pr edit $Pr --add-label ai-review | Out-Null
            Write-Output "REVIEW #${Pr}: the first-pass review found possible problems (PR comment), labelled ai-review"
            exit 4
        }
        $fpNote = if ($fpLine) { $fpLine } else { "first pass exit $($fp.ExitCode)" }
    }
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
# Best effort after a successful merge: under 'Stop', PowerShell 5.1 turns gh's stderr (the branch
# is usually auto-deleted already: HTTP 404) into a terminating error, which made a merged PR exit 1.
$ErrorActionPreference = 'Continue'
try { & gh api -X DELETE "repos/{owner}/{repo}/git/refs/heads/$($p.headRefName)" 2>$null | Out-Null } catch { }
if ($Reviewed) { try { & gh pr edit $Pr --remove-label ai-review 2>$null | Out-Null } catch { } }
Write-Output "MERGED #$Pr ($($p.url))$(if ($rerun) { ' after one CI re-run' })$(if ($fpNote) { "; $fpNote" })"
exit 0
