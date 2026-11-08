# Look up an issue's model/runner in .claude/issue-routing.json.
# If the issue is not in the file yet, classify it from its labels and title,
# append it, and save. Existing entries are never reclassified.
#
# Usage:  powershell -NoProfile -File .claude/scripts/route-issue.ps1 -Number 42
# Output: one JSON object on stdout: {"number","title","model","runner","reason"}
# Exit:   0 on success, 1 on error.

param(
    [Parameter(Mandatory = $true)]
    [int]$Number
)

$ErrorActionPreference = 'Stop'

$routingPath = Join-Path $PSScriptRoot '..\issue-routing.json'
$routingPath = [System.IO.Path]::GetFullPath($routingPath)

function Read-Routing {
    if (-not (Test-Path $routingPath)) {
        return [pscustomobject]@{ version = 1; description = ''; rules = @(); issues = @() }
    }
    $raw = [System.IO.File]::ReadAllText($routingPath, [System.Text.Encoding]::UTF8)
    return $raw | ConvertFrom-Json
}

function Write-Routing($doc) {
    $sorted = @($doc.issues | Sort-Object { [int]$_.number })
    $out = [ordered]@{
        version     = $doc.version
        description = $doc.description
        rules       = @($doc.rules)
        issues      = $sorted
    }
    $json = $out | ConvertTo-Json -Depth 6
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($routingPath, $json + "`n", $enc)
}

function Get-Classification($issue) {
    $labels = @($issue.labels | ForEach-Object { $_.name })
    $title = [string]$issue.title
    $high = $labels -contains 'severity:high'
    $crypto = $labels -contains 'crypto'
    $sync = $labels -contains 'sync'

    # High-stakes checked first: a misroute of crypto/sync work costs more than a few tokens.
    if ($high -and ($crypto -or $sync)) {
        return @{ model = 'claude-opus-5.5'; runner = 'claude'; reason = 'severity:high crypto/sync design (auto-classified)' }
    }

    $docsOrTesting = ($title -match '^\[(Docs?|Testing)\]') -or ($labels -contains 'docs') -or ($labels -contains 'testing') -or ($labels -contains 'documentation')
    if (($labels -contains 'severity:low') -or ($labels -contains 'spec-inconsistency') -or $docsOrTesting) {
        $why = if ($labels -contains 'severity:low') { 'severity:low' } elseif ($labels -contains 'spec-inconsistency') { 'spec-inconsistency' } else { 'docs/testing' }
        return @{ model = 'gemini-3.8-flash'; runner = 'agy'; reason = "$why (auto-classified)" }
    }

    return @{ model = 'claude-sonnet-5.5'; runner = 'claude'; reason = 'default systems code (auto-classified)' }
}

$doc = Read-Routing
$existing = @($doc.issues) | Where-Object { [int]$_.number -eq $Number } | Select-Object -First 1

if ($existing) {
    $existing | ConvertTo-Json -Compress
    exit 0
}

$raw = & gh issue view $Number --json number,title,labels
if ($LASTEXITCODE -ne 0) {
    [Console]::Error.WriteLine("route-issue: gh could not load issue #$Number")
    exit 1
}
$issue = $raw | ConvertFrom-Json
$cls = Get-Classification $issue

$entry = [pscustomobject]@{
    number = [int]$issue.number
    title  = [string]$issue.title
    model  = $cls.model
    runner = $cls.runner
    reason = $cls.reason
}

$issues = New-Object System.Collections.ArrayList
foreach ($i in @($doc.issues)) { [void]$issues.Add($i) }
[void]$issues.Add($entry)
$doc.issues = $issues.ToArray()
Write-Routing $doc

$entry | ConvertTo-Json -Compress
exit 0
