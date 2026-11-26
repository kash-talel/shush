# First-pass PR review by Gemini 4 Hydrogen (agy CLI), a second model family next to Claude.
#
# Hydrogen reviews a read-only snapshot of the PR head (no .git, sandboxed agy in plan mode) and
# posts its result as a PR comment. It is a source of LEADS only: its verdict and severities are
# never used to merge anything. A finding can only ADD review (merge-pr.ps1 labels the PR
# ai-review); a clean result or an error never removes review.
# Replay tests (2026-11-26): caught 3 of 3 seeded bugs with no false alarms on a clean PR, but only
# about 1 in 5 of the real problems Opus later fixed (it misses compatibility and tool defaults).
#
# Usage:  powershell -NoProfile -File .claude/scripts/hydrogen-review.ps1 -Pr <number> [-TimeoutMinutes 25]
# Exit:   0 no findings   3 findings (posted on the PR)   7 unavailable (agy missing, timeout, bad output)
#         8 skipped (Markdown-only PR)
# A result for the same PR head is reused, not re-run (merge-pr.ps1 and the pr-reviewer both call this).
# Output: a few lines; with -Print also the findings text. -NoComment: test run, posts nothing.

param(
    [Parameter(Mandatory = $true)][int]$Pr,
    [int]$TimeoutMinutes = 25,
    [string]$Model = 'gemini-4-hydrogen-high',
    [switch]$Print,
    [switch]$NoComment   # testing: post nothing, ignore earlier results
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')
$Marker = 'hydrogen-review'

function Out-Result([int]$code, [string]$line, [string]$text) {
    Write-Output $line
    if ($Print -and $text) { Write-Output ''; Write-Output $text }
    exit $code
}

$p = (& gh pr view $Pr --json number,title,headRefOid,closingIssuesReferences) | ConvertFrom-Json
if (-not $p.headRefOid) { Out-Result 7 "HYDROGEN #${Pr}: unavailable: cannot read the PR" '' }
$oid = [string]$p.headRefOid

# --- reuse a result for this exact head ---
$prior = if ($NoComment) { @() } else { @(& gh api "repos/{owner}/{repo}/issues/$Pr/comments" --paginate --jq '.[] | @json' |
    Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object { ([string]$_.body).StartsWith("<!-- $Marker head=$oid ") }) }
if ($prior.Count -gt 0) {
    $b = [string]$prior[-1].body
    if ($b -match "^<!-- $Marker head=\w+ result=(\w+) -->") {
        $r = $Matches[1]
        if ($r -eq 'findings') { Out-Result 3 "HYDROGEN #${Pr}: FINDINGS (already posted for $($oid.Substring(0,9)))" $b }
        if ($r -eq 'clean') { Out-Result 0 "HYDROGEN #${Pr}: CLEAN (already checked $($oid.Substring(0,9)))" $b }
    }
}

$paths = Get-PrPaths $Pr
if ($paths.Count -gt 0 -and @($paths | Where-Object { $_ -notmatch '\.md$' }).Count -eq 0) {
    Out-Result 8 "HYDROGEN #${Pr}: skipped (Markdown only)" ''
}
$agy = Get-Command agy -ErrorAction SilentlyContinue
if (-not $agy) { Out-Result 7 "HYDROGEN #${Pr}: unavailable: agy is not on PATH" '' }

# --- snapshot of the PR head, outside every worktree ---
$repo = (& git -C $PSScriptRoot rev-parse --show-toplevel).Trim()
$work = Join-Path ([IO.Path]::GetTempPath()) "shush-hydrogen-$Pr-$([guid]::NewGuid().ToString('N').Substring(0,8))"
$snap = Join-Path $work 'repo'
New-Item -ItemType Directory -Force -Path $snap | Out-Null
$utf8 = New-Object Text.UTF8Encoding($false)
try {
    $ErrorActionPreference = 'Continue'   # git/gh write progress to stderr
    & git -C $repo fetch --quiet origin "pull/$Pr/head" 2>$null
    & git -C $repo cat-file -e "$oid^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) { Out-Result 7 "HYDROGEN #${Pr}: unavailable: cannot fetch head $oid" '' }
    $tar = Join-Path $work 'head.tar'
    & git -C $repo archive --format=tar -o $tar $oid
    # Windows' own tar: Git's tar misreads C:\ paths.
    & (Join-Path $env:SystemRoot 'System32\tar.exe') -xf $tar -C $snap
    if ($LASTEXITCODE -ne 0) { Out-Result 7 "HYDROGEN #${Pr}: unavailable: cannot unpack the snapshot" '' }
    Remove-Item -LiteralPath $tar -Force

    $issueNo = $null
    $refs = @($p.closingIssuesReferences)
    if ($refs.Count -gt 0) { $issueNo = [int]$refs[0].number }
    elseif ([string]$p.title -match '#(\d+)') { $issueNo = [int]$Matches[1] }
    $brief = if ($issueNo) { (& powershell -NoProfile -File (Join-Path $PSScriptRoot 'issue-brief.ps1') -Number $issueNo) -join "`n" } else { '(no linked issue)' }
    $diff = (& gh pr diff $Pr) -join "`n"
    if (-not $diff) { Out-Result 7 "HYDROGEN #${Pr}: unavailable: empty diff" '' }

    $task = [IO.File]::ReadAllText((Join-Path $PSScriptRoot 'hydrogen-review.md')) +
        "`n`nPULL REQUEST: #$Pr $($p.title)`n`nISSUE:`n$brief`n`nPULL REQUEST DIFF:`n$diff`n"
    [IO.File]::WriteAllText((Join-Path $snap 'REVIEW_TASK.md'), $task, $utf8)

    # --- run agy, bounded ---
    $out = Join-Path $work 'out.json'; $err = Join-Path $work 'err.txt'
    $prompt = 'Read REVIEW_TASK.md in the current directory (it is not part of the repository) and do exactly what it says. Do not edit any file.'
    $argLine = "-p `"$prompt`" --model $Model --mode plan --sandbox --output-format json"
    $proc = Start-Process -FilePath $agy.Source -ArgumentList $argLine -WorkingDirectory $snap `
        -RedirectStandardOutput $out -RedirectStandardError $err -NoNewWindow -PassThru
    $null = $proc.Handle   # keep the handle so ExitCode is readable later
    if (-not $proc.WaitForExit($TimeoutMinutes * 60 * 1000)) {
        & taskkill /T /F /PID $proc.Id 2>$null | Out-Null
        Out-Result 7 "HYDROGEN #${Pr}: unavailable: no answer within $TimeoutMinutes minutes" ''
    }

    $resp = $null
    try { $resp = ([IO.File]::ReadAllText($out) | ConvertFrom-Json).response } catch { }
    if (-not $resp) {
        $tail = if (Test-Path $err) { ((Get-Content -LiteralPath $err -Tail 3) -join ' ') } else { '' }
        Out-Result 7 "HYDROGEN #${Pr}: unavailable: agy exit $($proc.ExitCode), no response. $tail" ''
    }
    $resp = [regex]::Replace([string]$resp, '\]\(file:///[^)]*\)', ']')   # local links mean nothing on GitHub
    $resp = $resp.Replace("$snap\", '').Replace($snap.Replace('\', '/') + '/', '')
    $m = [regex]::Match($resp, '(?ms)^\W*FINDINGS\W*:?\s*(.*?)(?=^\W*CHECKED\W*:|\z)')
    if (-not $m.Success) { Out-Result 7 "HYDROGEN #${Pr}: unavailable: answer has no FINDINGS line" $resp }
    $clean = $m.Groups[1].Value.Trim() -match '^(none|no findings)\b'
    $result = if ($clean) { 'clean' } else { 'findings' }
    if ($resp.Length -gt 60000) { $resp = $resp.Substring(0, 60000) + "`n`n(truncated)" }

    $what = if ($clean) { 'No findings.' } else {
        'These are leads from a second model family, not verdicts. The PR goes to the Opus pr-reviewer, which confirms or rejects each one against the code.' }
    $body = Write-BodyFile ("<!-- $Marker head=$oid result=$result -->`n## First-pass review ($Model, automated)`n`n" +
        "Head ``$($oid.Substring(0,9))``. $what`n`n<details><summary>Hydrogen's answer</summary>`n`n$resp`n`n</details>`n")
    if (-not $NoComment) { & gh pr comment $Pr --body-file $body | Out-Null }
    Remove-Item $body -ErrorAction SilentlyContinue
    if ($clean) { Out-Result 0 "HYDROGEN #${Pr}: CLEAN ($($oid.Substring(0,9)))" $resp }
    Out-Result 3 "HYDROGEN #${Pr}: FINDINGS posted on the PR ($($oid.Substring(0,9)))" $resp
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
