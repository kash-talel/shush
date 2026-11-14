# Look up an issue's model/runner in .claude/issue-routing.json.
# If the issue is not in the file yet, classify it from its labels and title,
# append it, and save. Existing entries are never reclassified.
#
# Usage:  powershell -NoProfile -File .claude/scripts/route-issue.ps1 -Number 42
# Output: one JSON object on stdout:
#         {"number","title","model","runner","target","reason","merge","merge_reason"}
#         target = model to dispatch to: opus | sonnet (Agent tool) or an agy model id.
#         merge  = auto | review. review: the runner opens the PR labelled ai-review and
#                  stops; the pr-reviewer agent (Opus) verifies and merges it, escalating to the
#                  owner (label needs-review) only for a decision that is genuinely theirs.
#                  Computed from the issue's LIVE labels on
#                  every call (so an escalated issue flips to review), unless the entry pins a
#                  "merge" field by hand. If the labels cannot be read, it fails closed to review.
# Exit:   0 on success, 1 on error.

param(
    [Parameter(Mandatory = $true)]
    [int]$Number
)

$ErrorActionPreference = 'Stop'

# Always the MAIN checkout's file, even when run from an /issue worktree, so there is
# one routing table (worktree copies are stale snapshots of origin/main).
$gitCommon = (& git -C $PSScriptRoot rev-parse --path-format=absolute --git-common-dir 2>$null)
if ($LASTEXITCODE -eq 0 -and $gitCommon) {
    $mainRoot = Split-Path ([System.IO.Path]::GetFullPath($gitCommon.Trim())) -Parent
    $routingPath = Join-Path $mainRoot '.claude\issue-routing.json'
} else {
    $routingPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\issue-routing.json'))
}

function Read-Routing {
    if (-not (Test-Path $routingPath)) {
        return [pscustomobject]@{ version = 1; description = ''; rules = @(); issues = @() }
    }
    $raw = [System.IO.File]::ReadAllText($routingPath, [System.Text.Encoding]::UTF8)
    return $raw | ConvertFrom-Json
}

function Write-Routing($doc) {
    # One issue per line, so routing one issue is a one-line diff.
    $sorted = @($doc.issues | Sort-Object { [int]$_.number })
    # Windows PowerShell escapes ' < > & as \uXXXX; valid JSON, but noisy in diffs.
    $j = { param($v)
        (ConvertTo-Json -InputObject $v -Compress) -replace '(?<!\\)\\u0027', "'" -replace '(?<!\\)\\u0026', '&' -replace '(?<!\\)\\u003c', '<' -replace '(?<!\\)\\u003e', '>'
    }
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('{')
    $lines.Add('  "version": ' + (& $j ([int]$doc.version)) + ',')
    $lines.Add('  "description": ' + (& $j ([string]$doc.description)) + ',')
    $lines.Add('  "rules": [')
    $rules = @($doc.rules)
    for ($i = 0; $i -lt $rules.Count; $i++) { $lines.Add('    ' + (& $j ([string]$rules[$i])) + $(if ($i -lt $rules.Count - 1) { ',' } else { '' })) }
    $lines.Add('  ],')
    $lines.Add('  "issues": [')
    for ($i = 0; $i -lt $sorted.Count; $i++) {
        $e = $sorted[$i]
        $row = '{"number": ' + [int]$e.number +
            ', "title": ' + (& $j ([string]$e.title)) +
            ', "model": ' + (& $j ([string]$e.model)) +
            ', "runner": ' + (& $j ([string]$e.runner)) +
            ', "reason": ' + (& $j ([string]$e.reason)) +
            $(if ($e.PSObject.Properties['merge']) { ', "merge": ' + (& $j ([string]$e.merge)) } else { '' }) + '}'
        $lines.Add('    ' + $row + $(if ($i -lt $sorted.Count - 1) { ',' } else { '' }))
    }
    $lines.Add('  ]')
    $lines.Add('}')
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($routingPath, ($lines -join "`n") + "`n", $enc)
}

# Routing policy (v2, 2026-11-13). Claude writes every line of code, UI and tests; AGY only
# gets prose. Severity no longer decides the runner on its own: a severity:low UI tweak still
# needs taste, and AGY's output on #125-#127 had to be redone by Claude.
#   Opus   : severity:critical, or crypto/sync at severity:high (state machines, PAKE, merge design).
#   AGY    : explicitly docs/spec prose (title or label) with NO domain label and not high/critical.
#            The dispatcher also rejects any AGY PR that touches a non-doc path (agy-gate.ps1),
#            so a misroute fails closed.
#   Sonnet : everything else (all Rust, Svelte, Win32, tests, scripts, assets).
$DocsOnlyLabels = @('docs', 'documentation', 'spec-inconsistency', 'spec-review', 'enhancement', 'severity:low', 'severity:medium')

function Get-Classification($issue) {
    $labels = @($issue.labels | ForEach-Object { $_.name })
    $title = [string]$issue.title
    $critical = $labels -contains 'severity:critical'
    $high = $labels -contains 'severity:high'
    $cryptoOrSync = ($labels -contains 'crypto') -or ($labels -contains 'sync')

    if ($critical) {
        return @{ model = 'claude-opus-5.5'; runner = 'claude'; reason = 'severity:critical (auto-classified)' }
    }
    if ($high -and $cryptoOrSync) {
        return @{ model = 'claude-opus-5.5'; runner = 'claude'; reason = 'severity:high crypto/sync design (auto-classified)' }
    }

    $docsSignal = ($title -match '^\[(Docs?|Documentation|Spec)\]') -or
        ($labels -contains 'docs') -or ($labels -contains 'documentation') -or ($labels -contains 'spec-inconsistency')
    $domainLabels = @($labels | Where-Object { $DocsOnlyLabels -notcontains $_ })
    if ($docsSignal -and $domainLabels.Count -eq 0 -and -not $high) {
        return @{ model = 'gemini-3.8-flash'; runner = 'agy'; reason = 'docs/spec prose only (auto-classified)' }
    }

    return @{ model = 'claude-sonnet-5.5'; runner = 'claude'; reason = 'code, UI or tests (auto-classified)' }
}

# Merge policy (2026-11-13). Green checks are not enough where a subtle bug leaks secrets,
# corrupts a vault or ships a bad build, so those PRs wait for the owner. Everything else
# auto-merges once fmt/clippy/tests/check pass.
$ReviewLabels = @('crypto', 'sync', 'file-format', 'memory-hygiene', 'browser-integration',
    'severity:critical', 'severity:high')
$ReviewTitle = '^\[(Crypto|Sync|File format|Memory hygiene|Keyfile|Duress|Distribution|Release|Updater|Signing|CI|Pipeline|Security)\]'

function Get-MergePolicy($issue) {
    $labels = @($issue.labels | ForEach-Object { $_.name })
    $hits = @($labels | Where-Object { $ReviewLabels -contains $_ })
    if ($hits.Count -gt 0) { return @{ merge = 'review'; why = 'label ' + ($hits -join ', ') } }
    if ([string]$issue.title -match $ReviewTitle) { return @{ merge = 'review'; why = 'title ' + $Matches[0] } }
    return @{ merge = 'auto'; why = 'routine change' }
}

# The dispatch target for /issue: the Agent tool's model alias for claude issues,
# the agy CLI model id for agy issues. Computed on output only; never stored.
function Write-Entry($entry, $policy) {
    $target = switch ([string]$entry.model) {
        'claude-opus-5.5'   { 'opus' }
        'claude-sonnet-5.5' { 'sonnet' }
        'gemini-3.8-flash'  { 'gemini-3.8-flash-medium' }
        default             { if ($entry.runner -eq 'agy') { 'gemini-3.8-flash-medium' } else { 'sonnet' } }
    }
    $out = [ordered]@{
        number = [int]$entry.number
        title  = [string]$entry.title
        model  = [string]$entry.model
        runner = [string]$entry.runner
        target = $target
        reason = [string]$entry.reason
        merge  = [string]$policy.merge
        merge_reason = [string]$policy.why
    }
    [pscustomobject]$out | ConvertTo-Json -Compress
}

$doc = Read-Routing
$existing = @($doc.issues) | Where-Object { [int]$_.number -eq $Number } | Select-Object -First 1

$raw = & gh issue view $Number --json number,title,labels
$issue = if ($LASTEXITCODE -eq 0) { $raw | ConvertFrom-Json } else { $null }

if ($existing) {
    $pinned = if ($existing.PSObject.Properties['merge']) { [string]$existing.merge } else { '' }
    if ($pinned -eq 'auto' -or $pinned -eq 'review') {
        $policy = @{ merge = $pinned; why = 'pinned in issue-routing.json' }
    } elseif ($issue) {
        $policy = Get-MergePolicy $issue
    } else {
        $policy = @{ merge = 'review'; why = 'labels unavailable (fail closed)' }
    }
    Write-Entry $existing $policy
    exit 0
}

if (-not $issue) {
    [Console]::Error.WriteLine("route-issue: gh could not load issue #$Number")
    exit 1
}
$cls = Get-Classification $issue

$entry = [pscustomobject]@{
    number = [int]$issue.number
    title  = [string]$issue.title
    model  = $cls.model
    runner = $cls.runner
    reason = $cls.reason
}

# Read-modify-write under the shared lock: parallel dispatchers would otherwise drop each
# other's entries. Re-read inside the lock; if another runner routed this issue meanwhile,
# its entry wins (entries are never reclassified).
. (Join-Path $PSScriptRoot 'Guard.ps1')
$result = Invoke-Exclusive -Name 'routing' -Action {
    $doc = Read-Routing
    $raced = @($doc.issues) | Where-Object { [int]$_.number -eq $Number } | Select-Object -First 1
    if ($raced) { return $raced }
    $issues = New-Object System.Collections.ArrayList
    foreach ($i in @($doc.issues)) { [void]$issues.Add($i) }
    [void]$issues.Add($entry)
    $doc.issues = $issues.ToArray()
    Write-Routing $doc
    return $entry
}

Write-Entry $result (Get-MergePolicy $issue)
exit 0
