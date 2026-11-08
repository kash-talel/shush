# Isolated git worktrees for /issue runs, so a runner never touches the main checkout
# (which may hold the owner's uncommitted work).
#
#   -Create -Number 42   Make .claude/worktrees/issue-42 from a fresh origin/main (detached),
#                        link the shared build dirs, print the worktree path.
#   -Link                Link the shared build dirs into the CURRENT worktree (idempotent).
#                        Used by the Claude issue-worker inside an Agent-tool worktree.
#   -Remove -Path <dir>  Unlink the shared build dirs, then remove the worktree and prune.
#
# Shared build dirs (src/node_modules, src-tauri/target) are directory junctions to the main
# checkout, so a worktree needs no npm install and reuses the compiled Rust dependencies.
# Junctions are always unlinked BEFORE the worktree is deleted: a recursive delete must never
# follow them into the main checkout.

param(
    [switch]$Create,
    [switch]$Link,
    [switch]$Remove,
    [int]$Number = 0,
    [string]$Path = ''
)

$ErrorActionPreference = 'Stop'
$Shared = @('src\node_modules', 'src-tauri\target')

function Get-MainRoot {
    $common = (& git rev-parse --path-format=absolute --git-common-dir).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'not inside the shush git repository' }
    return (Split-Path ([System.IO.Path]::GetFullPath($common)) -Parent)
}

function Test-Link([string]$p) {
    if (-not (Test-Path -LiteralPath $p)) { return $false }
    return [bool]((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)
}

function Add-Links([string]$wt, [string]$main) {
    if ([IO.Path]::GetFullPath($wt).TrimEnd('\') -ieq $main.TrimEnd('\')) { return }  # never link main into itself
    foreach ($rel in $Shared) {
        $src = Join-Path $main $rel
        $dst = Join-Path $wt $rel
        if (-not (Test-Path -LiteralPath $src)) { continue }
        if (Test-Path -LiteralPath $dst) { continue }  # already linked, or a real dir the runner made
        New-Item -ItemType Directory -Force -Path (Split-Path $dst -Parent) | Out-Null
        New-Item -ItemType Junction -Path $dst -Target $src | Out-Null
    }
}

$main = Get-MainRoot

if ($Create) {
    if ($Number -le 0) { throw '-Create needs -Number' }
    $wt = Join-Path $main ".claude\worktrees\issue-$Number"
    if (Test-Path -LiteralPath $wt) { throw "worktree already exists: $wt (remove it with -Remove -Path)" }
    & git -C $main fetch --quiet origin main
    if ($LASTEXITCODE -ne 0) { throw 'git fetch origin main failed' }
    & git -C $main worktree add --quiet --detach $wt origin/main
    if ($LASTEXITCODE -ne 0) { throw 'git worktree add failed' }
    Add-Links $wt $main
    Write-Output $wt
    exit 0
}

if ($Link) {
    $wt = (& git rev-parse --show-toplevel).Trim()
    Add-Links ([IO.Path]::GetFullPath($wt)) $main
    Write-Output "linked: $wt"
    exit 0
}

if ($Remove) {
    if (-not $Path) { throw '-Remove needs -Path' }
    $wt = [IO.Path]::GetFullPath($Path)
    if ($wt.TrimEnd('\') -ieq $main.TrimEnd('\')) { throw 'refusing to remove the main checkout' }
    if (Test-Path -LiteralPath $wt) {
        foreach ($rel in $Shared) {
            $dst = Join-Path $wt $rel
            if (Test-Link $dst) { & cmd /c rmdir "$dst" | Out-Null }  # removes the link only
        }
        foreach ($rel in $Shared) {
            if (Test-Link (Join-Path $wt $rel)) { throw "could not unlink $rel; not removing $wt" }
        }
        & git -C $main worktree remove --force $wt
        if ($LASTEXITCODE -ne 0) { throw "git worktree remove failed for $wt" }
    }
    & git -C $main worktree prune
    Write-Output "removed: $wt"
    exit 0
}

throw 'use -Create -Number N, -Link, or -Remove -Path DIR'
