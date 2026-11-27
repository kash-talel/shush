# Local verification for /issue runners: fmt, clippy, tests, svelte-check. Prints one line per
# step and, for a failing step, only the part of its output needed to fix it.
#
# Usage:  powershell -NoProfile -File .claude/scripts/verify.ps1 [-Full] [-Test <name filter>]
#         -Full  run everything even when the change is Markdown-only
#         -Test  run only `cargo test <filter>` (quick re-check of one test)
# Exit:   0 all passed (or docs-only, skipped)   1 a step failed
# CI re-runs fmt/clippy/check/lib tests on a clean machine before merge-pr.ps1 merges.

param([switch]$Full, [string]$Test = '')

$ErrorActionPreference = 'Stop'
$root = (& git rev-parse --show-toplevel).Trim()
Set-Location $root
. (Join-Path $root '.claude\scripts\issue-env.ps1')

function Get-ChangedPaths {
    $a = @(& git diff --name-only origin/main...HEAD 2>$null)
    $b = @(& git diff --name-only HEAD 2>$null)
    $c = @(& git ls-files --others --exclude-standard 2>$null)
    return @($a + $b + $c | Where-Object { $_ } | Select-Object -Unique)
}

if (-not $Full -and -not $Test) {
    $changed = Get-ChangedPaths
    if ($changed.Count -gt 0 -and -not ($changed | Where-Object { $_ -notmatch '\.md$' })) {
        Write-Output "verify: docs-only change ($($changed.Count) .md file(s)); build and tests skipped"
        exit 0
    }
}

# Runs a command line through cmd so stderr is captured as text (PowerShell 5.1 would wrap it).
function Invoke-Step([string]$name, [string]$cmd, [scriptblock]$excerpt) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $out = @(& cmd /c "$cmd 2>&1")
    $code = $LASTEXITCODE
    $secs = [int]$sw.Elapsed.TotalSeconds
    # [Console] writes, not Write-Output: the function's return value must stay a lone bool.
    if ($code -eq 0) { [Console]::WriteLine("ok   $name (${secs}s)"); return $true }
    [Console]::WriteLine("FAIL $name (${secs}s, exit $code)")
    $lines = @(& $excerpt $out)
    if ($lines.Count -eq 0) { $lines = $out | Select-Object -Last 60 }
    $lines | Select-Object -First 150 | ForEach-Object { [Console]::WriteLine("     $_") }
    return $false
}

# Policy.ps1 self-check (cheap, so it runs whenever this does).
$selfcheck = @(& powershell -NoProfile -File (Join-Path $root '.claude\scripts\policy-selfcheck.ps1'))
if ($LASTEXITCODE -ne 0) { $selfcheck | ForEach-Object { [Console]::WriteLine($_) }; Write-Output 'verify: FAILED (policy self-check)'; exit 1 }

$manifest = '--manifest-path src-tauri/Cargo.toml'
$ok = $true

if ($Test) {
    $ok = Invoke-Step "cargo test $Test" "cargo test $manifest -q $Test" { param($o) $o | Select-String -Pattern '^(test .* FAILED|failures:|---- |thread |  left|  right|error)' -Context 0, 6 | ForEach-Object { $_.ToString() } }
    if ($ok) { exit 0 } else { exit 1 }
}

$ok = (Invoke-Step 'cargo fmt --check' "cargo fmt $manifest --check" { param($o) $o | Select-Object -First 80 }) -and $ok
$ok = (Invoke-Step 'cargo clippy' "cargo clippy $manifest --all-targets --message-format=short -- -D warnings" {
        param($o) $o | Where-Object { $_ -match '(error|warning)(\[\w+\])?:' } }) -and $ok
$ok = (Invoke-Step 'cargo test' "cargo test $manifest -q" {
        param($o)
        $i = [array]::IndexOf($o, ($o | Where-Object { $_ -match '^failures:' } | Select-Object -First 1))
        if ($i -ge 0) { $o[$i..($o.Count - 1)] } else { $o | Where-Object { $_ -match '^error|FAILED|panicked' } }
    }) -and $ok
Push-Location (Join-Path $root 'src')
try {
    $ok = (Invoke-Step 'npm run check' 'npm run check --silent' {
            param($o) $o | Where-Object { $_ -match 'Error|error|Warn|FAIL|fail' } }) -and $ok
} finally { Pop-Location }

if ($ok) { Write-Output 'verify: all passed'; exit 0 }
Write-Output 'verify: FAILED (fix, then rerun; use -Test <name> to re-check one test)'
exit 1
