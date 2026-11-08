# Helper script to fetch the next AGY-assigned issue from .claude/issue-routing.json
# Only Claude attributes issues to models; this script strictly obeys .claude/issue-routing.json.

param(
    [int]$Number = 0
)

$ErrorActionPreference = 'Stop'

$repoRoot = (Get-Item $PSScriptRoot).Parent.Parent.Parent.Parent.FullName
$routingPath = Join-Path $repoRoot '.claude\issue-routing.json'

if (-not (Test-Path $routingPath)) {
    [Console]::Error.WriteLine("Error: Routing file not found at $routingPath")
    exit 1
}

$routing = Get-Content $routingPath -Raw -Encoding UTF8 | ConvertFrom-Json

if ($Number -gt 0) {
    $entry = @($routing.issues) | Where-Object { [int]$_.number -eq $Number } | Select-Object -First 1
    if (-not $entry) {
        [Console]::Error.WriteLine("Issue #$Number is not recorded in .claude/issue-routing.json. Run /routing or classify in Claude first.")
        exit 1
    }
    if ($entry.runner -ne 'agy') {
        [Console]::Error.WriteLine("GATEKEEPER ALERT: Issue #$Number is assigned to $($entry.model) (runner: $($entry.runner)). Run it in Claude Code, not AGY!")
        exit 2
    }
    $entry | ConvertTo-Json -Compress
    exit 0
}

# Auto-pick mode: get live open issues from GitHub
$raw = & gh issue list --state open --limit 200 --json number,title,labels
if ($LASTEXITCODE -ne 0) {
    [Console]::Error.WriteLine("Failed to list open issues via gh.")
    exit 1
}

$openIssues = $raw | ConvertFrom-Json
$openSet = @{}
$openIssues | ForEach-Object { $openSet[[int]$_.number] = $_ }

function Get-SeverityRank($issue) {
    $labels = @($issue.labels | ForEach-Object { $_.name })
    if ($labels -contains 'severity:critical') { return 1 }
    if ($labels -contains 'severity:high') { return 2 }
    if ($labels -contains 'severity:medium') { return 3 }
    if ($labels -contains 'severity:low') { return 4 }
    return 5
}

$candidates = @($routing.issues) | Where-Object { 
    $_.runner -eq 'agy' -and $openSet.ContainsKey([int]$_.number) 
} | ForEach-Object {
    $live = $openSet[[int]$_.number]
    [PSCustomObject]@{
        number   = [int]$_.number
        title    = [string]$_.title
        model    = [string]$_.model
        runner   = [string]$_.runner
        reason   = [string]$_.reason
        severity = Get-SeverityRank $live
    }
} | Sort-Object { $_.severity }, { $_.number }

if ($candidates.Count -eq 0) {
    [Console]::WriteLine("ALL_DONE: No open issues currently assigned to AGY (Gemini 3.8 Flash).")
    exit 0
}

$chosen = $candidates[0]
$chosen | ConvertTo-Json -Compress
exit 0
