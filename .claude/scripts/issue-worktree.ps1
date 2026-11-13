# Isolated git worktrees for /issue runs, so a runner never touches the main checkout
# (which may hold the owner's uncommitted work), and parallel runners never share a build dir.
#
#   -Create -Number 42   Make .claude/worktrees/issue-42 from a fresh origin/main (detached),
#                        link the build dirs, print the worktree path.
#   -Link                Link the build dirs into the CURRENT worktree (idempotent).
#                        Used by the Claude issue-worker inside an Agent-tool worktree.
#   -OwnNodeModules      Replace the CURRENT worktree's shared node_modules junction with its own
#                        `npm ci` install. Needed before any change to src/package*.json.
#   -Remove -Path <dir>  Stop processes holding files in the worktree, unlink the build dirs,
#                        release its target slot, remove the worktree and prune.
#   -Status              Show the target-slot pool and which worktree holds each slot.
#
# Build dirs:
# - src/node_modules  -> junction to the MAIN checkout's, read-only by convention. Only linked
#   when the worktree's src/package-lock.json matches main's; otherwise the runner must run
#   -OwnNodeModules. Never run npm install/ci/update through the junction: it rewrites main's tree.
# - src-tauri/target  -> junction to a LEASED slot in .claude/cargo-targets/slot-<k>. One worktree
#   per slot at a time, so two cargo processes never write the same target (shared targets give
#   "Access is denied (os error 5)" when one run relinks a test exe another is executing). Slots
#   are reused across issues, so dependencies stay compiled: only the shush crates rebuild.
#   A slot's lease is live while the worktree it names still exists, so a crashed run's slot is
#   reclaimed automatically once its worktree is removed; no PID tracking is involved.
#
# Junctions are always unlinked BEFORE the worktree is deleted: a recursive delete must never
# follow them into the main checkout or a slot.

param(
    [switch]$Create,
    [switch]$Link,
    [switch]$OwnNodeModules,
    [switch]$Remove,
    [switch]$Status,
    [int]$Number = 0,
    [string]$Path = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Guard.ps1')

$MaxSlots = 4   # each warm debug slot is several GB; raise only if more runners truly run at once
$Junctions = @('src\node_modules', 'src-tauri\target')

function Get-MainRoot {
    $common = (& git -C $PSScriptRoot rev-parse --path-format=absolute --git-common-dir).Trim()
    if ($LASTEXITCODE -ne 0) { throw 'not inside the shush git repository' }
    return (Split-Path ([IO.Path]::GetFullPath($common)) -Parent)
}

function Get-Full([string]$p) { return [IO.Path]::GetFullPath($p).TrimEnd('\') }

function Test-Link([string]$p) {
    if (-not (Test-Path -LiteralPath $p)) { return $false }
    return [bool]((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)
}

function Remove-Link([string]$p) {
    if (Test-Link $p) { & cmd /c rmdir "$p" | Out-Null }   # removes the link only, never the target
    if (Test-Link $p) { throw "could not unlink $p" }
}

function Get-PoolDir([string]$main) {
    $pool = Join-Path $main '.claude\cargo-targets'
    if (-not (Test-Path -LiteralPath $pool)) {
        New-Item -ItemType Directory -Force -Path $pool | Out-Null
        [IO.File]::WriteAllText((Join-Path $pool '.gitignore'), "*`n")   # self-ignoring
    }
    return $pool
}

function Read-Lease([string]$file) {
    if (-not (Test-Path -LiteralPath $file)) { return $null }
    $t = [IO.File]::ReadAllText($file).Trim()
    if ($t) { return $t } else { return $null }
}

# Returns the slot directory leased to $wt, acquiring a free or stale one if needed.
function Get-SlotLease([string]$main, [string]$wt) {
    $pool = Get-PoolDir $main
    return Invoke-Exclusive -Name 'target-slots' -Action {
        $free = $null
        for ($k = 0; $k -lt $MaxSlots; $k++) {
            $lease = Join-Path $pool "slot-$k.lease"
            $holder = Read-Lease $lease
            if ($holder -and ($holder -ieq $wt)) { return (Join-Path $pool "slot-$k") }   # already ours
            $stale = (-not $holder) -or (-not (Test-Path -LiteralPath $holder))
            if ($stale -and $null -eq $free) { $free = $k }
        }
        if ($null -eq $free) {
            throw "all $MaxSlots cargo target slots are leased (see -Status); finish or -Remove a worktree first"
        }
        [IO.File]::WriteAllText((Join-Path $pool "slot-$free.lease"), $wt)
        $dir = Join-Path $pool "slot-$free"
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
        return $dir
    }
}

function Clear-SlotLease([string]$main, [string]$wt) {
    $pool = Get-PoolDir $main
    Invoke-Exclusive -Name 'target-slots' -Action {
        for ($k = 0; $k -lt $MaxSlots; $k++) {
            $lease = Join-Path $pool "slot-$k.lease"
            if ((Read-Lease $lease) -ieq $wt) { Remove-Item -LiteralPath $lease -Force }
        }
    }
}

function Get-FileHashOrNull([string]$p) {
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    return (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
}

function Add-Links([string]$wt, [string]$main) {
    if ($wt -ieq $main) { return }   # never link the main checkout into itself

    # node_modules: share main's only if the lockfiles match.
    $nmDst = Join-Path $wt 'src\node_modules'
    $nmSrc = Join-Path $main 'src\node_modules'
    if (-not (Test-Path -LiteralPath $nmDst) -and (Test-Path -LiteralPath $nmSrc)) {
        $same = (Get-FileHashOrNull (Join-Path $wt 'src\package-lock.json')) -eq (Get-FileHashOrNull (Join-Path $main 'src\package-lock.json'))
        if ($same) {
            New-Item -ItemType Junction -Path $nmDst -Target $nmSrc | Out-Null
        } else {
            [Console]::Error.WriteLine('note: src/package-lock.json differs from main; run -OwnNodeModules for a private npm ci')
        }
    }

    # target: always a leased slot. A pre-existing real dir (made by a build before linking) is
    # left alone; it is private to this worktree and just builds cold.
    $tDst = Join-Path $wt 'src-tauri\target'
    if (-not (Test-Path -LiteralPath $tDst)) {
        $slot = Get-SlotLease $main $wt
        New-Item -ItemType Junction -Path $tDst -Target $slot | Out-Null
        [Console]::Error.WriteLine("target: $(Split-Path $slot -Leaf)")
    } elseif (Test-Link $tDst) {
        $null = Get-SlotLease $main $wt   # refresh/confirm the lease (idempotent)
    }
}

# Kill processes that keep files in the worktree open: the debug app and WebView2 children
# started from it, dev servers, cargo/rustc. Matched by executable path or command line
# containing the worktree path (or its slot), so nothing outside this run is touched.
function Stop-WorktreeProcesses([string]$wt, [string]$slot) {
    $needles = @("$wt\")   # trailing \ so issue-4 never matches issue-42
    if ($slot) { $needles += "$slot\" }
    foreach ($p in (Get-CimInstance Win32_Process)) {
        if ($p.ProcessId -eq $PID) { continue }
        $exe = [string]$p.ExecutablePath
        $cmd = [string]$p.CommandLine
        $hit = $false
        foreach ($n in $needles) {
            if ($exe.StartsWith($n, [StringComparison]::OrdinalIgnoreCase) -or
                $cmd.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit = $true; break }
        }
        if (-not $hit) { continue }
        try {
            Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
            [Console]::Error.WriteLine("stopped: $($p.Name) ($($p.ProcessId))")
        } catch {}
    }
}

$main = Get-Full (Get-MainRoot)

if ($Create) {
    if ($Number -le 0) { throw '-Create needs -Number' }
    $wt = Join-Path $main ".claude\worktrees\issue-$Number"
    if (Test-Path -LiteralPath $wt) { throw "worktree already exists: $wt (remove it with -Remove -Path)" }
    & git -C $main fetch --quiet origin main
    if ($LASTEXITCODE -ne 0) { throw 'git fetch origin main failed' }
    & git -C $main worktree add --quiet --detach $wt origin/main
    if ($LASTEXITCODE -ne 0) { throw 'git worktree add failed' }
    Add-Links (Get-Full $wt) $main
    Write-Output $wt
    exit 0
}

if ($Link) {
    $wt = Get-Full ((& git rev-parse --show-toplevel).Trim())
    Add-Links $wt $main
    Write-Output "linked: $wt"
    exit 0
}

if ($OwnNodeModules) {
    $wt = Get-Full ((& git rev-parse --show-toplevel).Trim())
    if ($wt -ieq $main) { throw '-OwnNodeModules is for /issue worktrees, not the main checkout' }
    $nm = Join-Path $wt 'src\node_modules'
    Remove-Link $nm
    Push-Location (Join-Path $wt 'src')
    try {
        & npm ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
    } finally { Pop-Location }
    Write-Output "private node_modules installed in $wt"
    exit 0
}

if ($Remove) {
    if (-not $Path) { throw '-Remove needs -Path' }
    $wt = Get-Full $Path
    if ($wt -ieq $main) { throw 'refusing to remove the main checkout' }
    if (Test-Path -LiteralPath $wt) {
        $tLink = Join-Path $wt 'src-tauri\target'
        $slot = $null
        if (Test-Link $tLink) { $slot = Get-Full ((Get-Item -LiteralPath $tLink -Force).Target | Select-Object -First 1) }
        Stop-WorktreeProcesses $wt $slot
        foreach ($rel in $Junctions) { Remove-Link (Join-Path $wt $rel) }
        $removed = $false
        for ($try = 1; $try -le 4 -and -not $removed; $try++) {
            & git -C $main worktree remove --force $wt 2>$null
            if ($LASTEXITCODE -eq 0) { $removed = $true; break }
            Start-Sleep -Milliseconds (500 * $try)   # AV scanners and exiting processes release handles late
            Stop-WorktreeProcesses $wt $null
        }
        if (-not $removed) { throw "git worktree remove failed for $wt (files still in use?)" }
    }
    Clear-SlotLease $main $wt
    & git -C $main worktree prune
    Write-Output "removed: $wt"
    exit 0
}

if ($Status) {
    $pool = Get-PoolDir $main
    for ($k = 0; $k -lt $MaxSlots; $k++) {
        $holder = Read-Lease (Join-Path $pool "slot-$k.lease")
        $built = Test-Path -LiteralPath (Join-Path $pool "slot-$k\debug")
        $state = if (-not $holder) { 'free' } elseif (Test-Path -LiteralPath $holder) { "leased by $holder" } else { "stale (was $holder)" }
        Write-Output ("slot-{0}: {1}{2}" -f $k, $state, $(if ($built) { ', warm' } else { '' }))
    }
    exit 0
}

throw 'use -Create -Number N, -Link, -OwnNodeModules, -Remove -Path DIR, or -Status'
