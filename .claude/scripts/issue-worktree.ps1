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
#                        release its target slot, remove the worktree and prune. Releases a
#                        Claude Code agent lock left by a finished agent (see Unlock-AgentWorktree).
#   -Status              Show the target-slot pool and which worktree holds each slot.
#   -Prune               Remove leftover agent-*/issue-* worktrees whose work is pushed or merged
#                        (run by issue-next.ps1 before every /issue).
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
    [switch]$Prune,
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
        # Fresh lease: the slot's scratch vault (issue-env.ps1) belongs to the previous issue.
        $e2e = Join-Path $slot 'e2e'
        if (Test-Path -LiteralPath $e2e) { Remove-Item -LiteralPath $e2e -Recurse -Force -ErrorAction SilentlyContinue }
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

# Run a native command whose failure is handled by its exit code. Under 'Stop', Windows
# PowerShell 5.1 turns any stderr line into a terminating error even with 2>$null, which used to
# end the retry loop below (and issue-finish.ps1) on the first failed `git worktree remove`.
function Invoke-Native([scriptblock]$Command) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $Command 2>$null | Out-Null } finally { $ErrorActionPreference = $old }
    return $LASTEXITCODE
}

# The lock reason git records for a worktree, '' if it is locked without one, $null if unlocked.
# -z because a free-text reason may contain a newline.
function Get-WorktreeLock([string]$wt) {
    $raw = (& git -C $main worktree list --porcelain -z) -join "`n"
    $cur = $null
    foreach ($field in ($raw -split "`0")) {
        if ($field -like 'worktree *') { $cur = Get-Full $field.Substring(9) }
        elseif ($cur -ieq $wt -and $field -match '^locked(?: (?<r>[\s\S]*))?$') { return [string]$Matches['r'] }
    }
    return $null
}

# Claude Code locks an Agent-tool worktree ("claude agent agent-<id> (pid <n>)") for as long as
# the agent counts as alive, which includes any background task or Monitor it left running after
# its final report. Only those locks are ever released here; a lock with any other reason (one
# the owner set by hand) is respected. -Remove callers have already decided the run is over, so
# they release the lock outright; -Prune only releases it when the locking process is gone.
function Unlock-AgentWorktree([string]$wt, [bool]$OnlyIfStale) {
    $reason = Get-WorktreeLock $wt
    if ($null -eq $reason) { return $true }
    $one = ($reason -replace '\s+', ' ').Trim()
    if ($one -notmatch '^claude agent .*\(pid (?<pid>\d+)\)$') { return $false }
    if ($OnlyIfStale -and (Get-Process -Id ([int]$Matches['pid']) -ErrorAction SilentlyContinue)) { return $false }
    if ((Invoke-Native { git -C $main worktree unlock $wt }) -ne 0) { return $false }
    Write-Host "note: released Claude agent lock on $wt ($one)"
    return $true
}

function Remove-Worktree([string]$wt, [bool]$StaleLockOnly = $false) {
    if ($wt -ieq $main) { throw 'refusing to remove the main checkout' }
    if (Test-Path -LiteralPath $wt) {
        if (-not (Unlock-AgentWorktree $wt $StaleLockOnly)) { throw "worktree is locked ($(Get-WorktreeLock $wt)): $wt" }
        $tLink = Join-Path $wt 'src-tauri\target'
        $slot = $null
        if (Test-Link $tLink) { $slot = Get-Full ((Get-Item -LiteralPath $tLink -Force).Target | Select-Object -First 1) }
        Stop-WorktreeProcesses $wt $slot
        foreach ($rel in $Junctions) { Remove-Link (Join-Path $wt $rel) }
        $removed = $false
        for ($try = 1; $try -le 4 -and -not $removed; $try++) {
            if ((Invoke-Native { git -C $main worktree remove --force $wt }) -eq 0) { $removed = $true; break }
            Start-Sleep -Milliseconds (500 * $try)   # AV scanners and exiting processes release handles late
            Stop-WorktreeProcesses $wt $null
        }
        if (-not $removed) { throw "git worktree remove failed for $wt (files still in use?)" }
    }
    Clear-SlotLease $main $wt
    & git -C $main worktree prune
    Write-Output "removed: $wt"
}

if ($Remove) {
    if (-not $Path) { throw '-Remove needs -Path' }
    Remove-Worktree (Get-Full $Path)
    exit 0
}

# Remove leftover /issue worktrees (agent-* and issue-* under .claude/worktrees) whose work is
# safe elsewhere: no uncommitted changes, AND either every commit is on a remote branch or HEAD
# is part of a merged/closed PR. Worktrees touched in the last 2 hours are left alone, since a
# parallel runner may still be using them.
if ($Prune) {
    $root = Get-Full (Join-Path $main '.claude\worktrees')
    $list = @(& git -C $main worktree list --porcelain | Where-Object { $_ -like 'worktree *' } | ForEach-Object { Get-Full $_.Substring(9) })
    $kept = 0
    foreach ($wt in $list) {
        if (-not $wt.StartsWith("$root\", [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ((Split-Path $wt -Leaf) -notmatch '^(agent-|issue-)') { continue }
        if (-not (Test-Path -LiteralPath $wt)) { continue }
        $gitDir = (& git -C $wt rev-parse --absolute-git-dir 2>$null)
        $stamp = @('logs\HEAD', 'HEAD') | ForEach-Object { Join-Path "$gitDir".Trim() $_ } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if ($stamp -and ((Get-Date) - (Get-Item -LiteralPath $stamp).LastWriteTime).TotalHours -lt 2) { $kept++; continue }
        $dirty = @(& git --no-optional-locks -C $wt status --porcelain --untracked-files=normal 2>$null | Where-Object { $_ -notmatch '^\?\? (src/node_modules|src-tauri/target)' })
        if ($dirty.Count -gt 0) { $kept++; continue }
        $unpushed = @(& git -C $wt log HEAD --not --remotes --oneline 2>$null)
        $safe = $unpushed.Count -eq 0
        if (-not $safe) {
            $sha = (& git -C $wt rev-parse HEAD).Trim()
            $prs = (& gh pr list --state all --search $sha --json state --jq '[.[] | select(.state != "OPEN")] | length' 2>$null)
            $safe = ([int]"0$prs") -gt 0
        }
        if ($safe) {
            try { Remove-Worktree $wt $true } catch { [Console]::Error.WriteLine("prune: could not remove ${wt}: $_"); $kept++ }
        } else { $kept++ }
    }
    Write-Output "prune: done ($kept kept)"
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
