# The ONE place that decides how an issue is routed and whether a change needs review.
# Dot-source it; every other script and prompt points here instead of keeping its own copy.
#
#   Get-Route $issue        -> @{ model; runner; target; reason }   (from live labels + title)
#   Get-MergePolicy $issue  -> @{ merge = 'auto'|'review'; why }    (from live labels + title)
#   Get-PrFiles $pr         -> objects { path; previous; status } for every file, all pages,
#                              including the OLD path of a rename
#   Get-SensitivePaths $paths -> the paths that force review whatever the issue's labels say
#
# First-pass review (hydrogen-review.ps1): Gemini 4 Hydrogen reads every Claude PR. It can only
# ADD review (a finding labels a routine PR ai-review); its verdict and severities are never used.
#
# Nothing is stored: routing is a pure function of the issue, so a label added later (for
# example severity:critical) changes the route on the next run. To pin a route by hand, put a
# label on the issue:
#   route:opus       run on Claude Opus
#   route:claude     run on Claude Sonnet, never AGY (agy-gate.ps1 adds it after a rejection)
#   review-required  always merge through the pr-reviewer
# Parking labels (the selector skips these issues): blocked, agent-failed.

[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)   # gh speaks UTF-8 (titles use – and ·)

$ReviewLabels = @('crypto', 'sync', 'file-format', 'memory-hygiene', 'browser-integration',
    'severity:critical', 'severity:high', 'review-required')

# Matched against EVERY part of the leading [A/B] tag, case-insensitive.
$ReviewTitleWords = @('Crypto', 'Sync', 'File format', 'Memory hygiene', 'Keyfile', 'Duress',
    'Distribution', 'Release', 'Update', 'Updates', 'Updater', 'Signing', 'CI', 'Pipeline',
    'Security', 'Network', 'Browser')

# A diff touching any of these goes to the pr-reviewer even when the issue looks routine.
# Prefixes end in '/'; anything else is an exact file or a file-name prefix.
# Deliberately NOT listed: src-tauri/src/lib.rs and main.rs. They hold most #[tauri::command]
# handlers (including the unlock commands and the Windows Hello evict(...) calls), but listing
# them would send almost every code PR to the pr-reviewer. The first-pass review
# (hydrogen-review.ps1) and the CI tests cover them; an issue that changes those calls should
# carry a review label (crypto / memory-hygiene). Revisit if that proves too weak.
# policy-selfcheck.ps1 (run by verify.ps1) asserts the entries below stay present.
$SensitivePrefixes = @(
    'src-tauri/src/crypto/', 'src-tauri/src/vault/', 'src-tauri/src/update/',
    'src-tauri/src/bridge/', 'src-tauri/src/sync/', 'src-tauri/src/bin/',
    'src-tauri/src/os/memory', 'src-tauri/src/os/clipboard', 'src-tauri/src/os/pipe',
    'src-tauri/src/os/native_host', 'src-tauri/src/os/session', 'src-tauri/src/os/private_dir',
    'src-tauri/src/os/win_hello', 'src-tauri/src/totp/',
    'src-tauri/src/os/ancestry', 'src-tauri/src/os/replace', 'src-tauri/src/os/recycle',
    'src-tauri/src/net',
    'src-tauri/Cargo.toml', 'src-tauri/Cargo.lock', 'src-tauri/tauri.conf.json', 'src-tauri/build.rs',
    'src-tauri/capabilities/', 'src-tauri/permissions/', 'src-tauri/windows/', 'src-tauri/windows-app-manifest',
    'src/package.json', 'src/package-lock.json', 'extension/',
    '.github/', '.claude/', '.agents/', '.cargo/', 'scripts/',
    'docs/spec/', 'docs/FORMAT.md', 'docs/testing/',
    'SECURITY.md', 'CLAUDE.md', 'GEMINI.md', 'AGENTS.md', 'release-please-config.json', '.release-please-manifest.json'
)

$ParkLabels = @('blocked', 'agent-failed')

function Get-LabelNames($issue) { return @($issue.labels | ForEach-Object { [string]$_.name }) }

function Get-Route($issue) {
    $labels = Get-LabelNames $issue
    $title = [string]$issue.title
    $opus = @{ model = 'claude-opus-5.5'; runner = 'claude'; target = 'opus' }
    $sonnet = @{ model = 'claude-sonnet-5.5'; runner = 'claude'; target = 'sonnet' }

    if ($labels -contains 'route:opus') { return $opus + @{ reason = 'pinned by label route:opus' } }
    if ($labels -contains 'severity:critical') { return $opus + @{ reason = 'severity:critical' } }
    $high = $labels -contains 'severity:high'
    if ($high -and (($labels -contains 'crypto') -or ($labels -contains 'sync'))) {
        return $opus + @{ reason = 'severity:high crypto/sync' }
    }
    if ($labels -contains 'route:claude') { return $sonnet + @{ reason = 'pinned by label route:claude' } }

    # AGY: explicitly docs/spec prose, no domain label, not high. agy-gate.ps1 still rejects any
    # non-doc path, so a misroute fails closed.
    $docsOnly = @('docs', 'documentation', 'spec-inconsistency', 'spec-review', 'enhancement', 'severity:low', 'severity:medium')
    $docsSignal = ($title -match '^\[(Docs?|Documentation|Spec)\]') -or
        ($labels -contains 'docs') -or ($labels -contains 'documentation') -or ($labels -contains 'spec-inconsistency')
    $domain = @($labels | Where-Object { $docsOnly -notcontains $_ })
    if ($docsSignal -and $domain.Count -eq 0 -and -not $high) {
        return @{ model = 'gemini-4-hydrogen'; runner = 'agy'; target = 'gemini-4-hydrogen-high'; reason = 'docs/spec prose only' }
    }
    return $sonnet + @{ reason = 'code, UI or tests' }
}

function Get-MergePolicy($issue) {
    $labels = Get-LabelNames $issue
    $hits = @($labels | Where-Object { $ReviewLabels -contains $_ })
    if ($hits.Count -gt 0) { return @{ merge = 'review'; why = 'label ' + ($hits -join ', ') } }
    if ([string]$issue.title -match '^\s*\[([^\]]+)\]') {
        foreach ($part in ($Matches[1] -split '/')) {
            $w = $part.Trim()
            if ($ReviewTitleWords | Where-Object { $_ -ieq $w }) { return @{ merge = 'review'; why = "title [$w]" } }
        }
    }
    return @{ merge = 'auto'; why = 'routine change (the diff is still path-checked before merge)' }
}

function Test-SensitivePath([string]$p) {
    $p = $p.Replace('\', '/').TrimStart('/')
    foreach ($s in $SensitivePrefixes) {
        if ($p.StartsWith($s, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-SensitivePaths([string[]]$paths) {
    return @($paths | Where-Object { $_ -and (Test-SensitivePath $_) } | Select-Object -Unique)
}

# All changed files of a PR via REST (paginated, so no 100-file cap). A rename lists both paths.
function Get-PrFiles($pr) {
    # No double quotes inside the jq program: PowerShell 5.1 splits native arguments on them.
    $rows = & gh api "repos/{owner}/{repo}/pulls/$pr/files" --paginate --jq '.[] | [.filename, .previous_filename, .status] | @tsv'
    if ($LASTEXITCODE -ne 0) { throw "cannot list files of PR $pr" }
    return @($rows | Where-Object { $_ } | ForEach-Object {
        $f = $_ -split "`t"
        [pscustomobject]@{ path = $f[0]; previous = $f[1]; status = $f[2] }
    })
}

# Every path a PR touches, old and new names of renames included.
function Get-PrPaths($pr) {
    return @(Get-PrFiles $pr | ForEach-Object { $_.path; if ($_.previous) { $_.previous } } | Select-Object -Unique)
}

# gh JSON -> array of objects. PowerShell 5.1's ConvertFrom-Json emits a JSON array as ONE
# pipeline object, so @(... | ConvertFrom-Json) would be a one-element array holding the array.
function ConvertFrom-GhJson { param([Parameter(ValueFromPipeline = $true)][string[]]$Text)
    begin { $buf = New-Object System.Text.StringBuilder }
    process { foreach ($t in $Text) { [void]$buf.AppendLine($t) } }
    end { $s = $buf.ToString().Trim(); if ($s) { ($s | ConvertFrom-Json) | ForEach-Object { $_ } } }
}

function Get-RepoOwner {
    $o = & gh repo view --json owner --jq '.owner.login'
    if ($LASTEXITCODE -ne 0 -or -not $o) { throw 'cannot read the repository owner' }
    return ([string]$o).Trim()
}

# gh --body with quotes breaks under Windows PowerShell 5.1; always go through a file.
function Write-BodyFile([string]$text) {
    $f = [IO.Path]::Combine([IO.Path]::GetTempPath(), "shush-body-$([guid]::NewGuid().ToString('N')).md")
    [IO.File]::WriteAllText($f, $text, (New-Object Text.UTF8Encoding($false)))
    return $f
}
