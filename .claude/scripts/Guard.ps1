# Cross-process mutual exclusion for the /issue pipeline. Dot-source it, then:
#
#     Invoke-Exclusive -Name 'routing' -Action { ...short critical section... }
#
# The lock is an exclusive open (FileShare.None) of .git/shush-locks/<Name>.lock in the shared
# git dir, so every worktree and every runner contends on the same file.
#
# Why this is enough (and why there is no PID bookkeeping):
# - The OS owns the lock. If the holder crashes or is killed, Windows closes the handle and the
#   lock is free; there is no stale lock file to reclaim and so no PID-reuse window to reason about.
# - .NET opens files with bInheritHandle = FALSE unless FileShare.Inheritable is passed, so a child
#   process cannot keep the lock alive. Critical sections also never start child processes.
# - Waiters back off exponentially with jitter, so parallel runners do not retry in lockstep.
#
# Keep critical sections to pure file I/O measured in milliseconds. Long work (gh, git, cargo)
# belongs outside the lock; re-read shared state inside it before writing.

function Get-ShushLockDir {
    $common = (& git -C $PSScriptRoot rev-parse --path-format=absolute --git-common-dir 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $common) { throw 'Guard: not inside the shush git repository' }
    $dir = Join-Path ([IO.Path]::GetFullPath($common.Trim())) 'shush-locks'
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    return $dir
}

function Invoke-Exclusive {
    param(
        [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9-]+$')][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [int]$TimeoutMs = 60000
    )
    $path = Join-Path (Get-ShushLockDir) "$Name.lock"
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMs)
    $attempt = 0
    $stream = $null
    while (-not $stream) {
        try {
            $stream = [IO.File]::Open($path, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        } catch [System.IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) { throw "Guard: timed out after $TimeoutMs ms waiting for lock '$Name' ($path)" }
            $attempt++
            $cap = [Math]::Min(2000, 25 * [Math]::Pow(2, [Math]::Min($attempt, 7)))
            Start-Sleep -Milliseconds (Get-Random -Minimum ([int]($cap / 2)) -Maximum ([int]$cap + 1))
        }
    }
    try { & $Action } finally { $stream.Dispose() }
}
