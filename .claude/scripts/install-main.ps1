# Build the latest origin/main as a release installer and install it over the owner's shush,
# so every merged issue can be tried in the real app. Stopgap until the signed update feed
# (#103) and the in-app updater (#78) exist.
#
#     powershell -NoProfile -File .claude/scripts/install-main.ps1            # build + install
#     powershell -NoProfile -File .claude/scripts/install-main.ps1 -CloseApp -Launch
#     powershell -NoProfile -File .claude/scripts/install-main.ps1 -Status
#
#   -Ref <ref>   What to build (default origin/main). Any fetched ref or commit works.
#   -CloseApp    Close a running installed shush first. Without it the script stops and asks
#                you to quit shush yourself (it never kills the app on its own).
#   -Launch      Start shush after installing.
#   -Force       Rebuild and reinstall even if this commit is already installed.
#   -Status      Print what is installed and exit.
#
# How it stays out of the way:
# - Builds in its own detached worktree, .claude/worktrees/install-main, with its own
#   node_modules and a persistent release target dir, so the main checkout (and any /issue
#   worktree or cargo slot) is never touched and rebuilds after the first one are incremental.
# - Before installing, copies every vault file it can find (%APPDATA%\com.shush.vault plus the
#   .shush paths listed in vaults.json) to %LOCALAPPDATA%\shush-install-main\backups\<stamp>.
#   Unreleased main may change the vault format; the copies are ciphertext, the last 10 are kept.
# - The NSIS installer runs silently (/S) in update mode: it replaces the program files only.
#   The vault, settings and WebView2 profile stay where they are.
# - It never dot-sources issue-env.ps1, so no scratch-vault or CDP variables leak into the
#   installed app when -Launch starts it.

param(
    [string]$Ref = 'origin/main',
    [switch]$CloseApp,
    [switch]$Launch,
    [switch]$Force,
    [switch]$Status
)

$ErrorActionPreference = 'Stop'

function Step([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Note([string]$msg) { Write-Host "    $msg" }

$common = (& git -C $PSScriptRoot rev-parse --path-format=absolute --git-common-dir).Trim()
if ($LASTEXITCODE -ne 0) { throw 'not inside the shush git repository' }
$main = Split-Path ([IO.Path]::GetFullPath($common)) -Parent
$wt = Join-Path $main '.claude\worktrees\install-main'
$state = Join-Path $env:LOCALAPPDATA 'shush-install-main'
$stateFile = Join-Path $state 'installed.json'
New-Item -ItemType Directory -Force -Path $state | Out-Null

function Get-Installed {
    $keys = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -eq 'shush' }
    $k = $keys | Select-Object -First 1
    if (-not $k) { return $null }
    $dir = Split-Path ($k.UninstallString.Trim('"')) -Parent
    return [pscustomobject]@{ Version = $k.DisplayVersion; Dir = $dir; Exe = (Join-Path $dir 'shush.exe') }
}

function Get-LastInstall {
    if (-not (Test-Path -LiteralPath $stateFile)) { return $null }
    try { return Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json } catch { return $null }
}

function Get-RunningApp([string]$dir) {
    if (-not $dir) { return @() }
    $prefix = $dir.TrimEnd('\') + '\'
    return @(Get-Process shush -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and $_.Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
    })
}

$installed = Get-Installed
$last = Get-LastInstall

if ($Status) {
    if ($installed) { "installed: shush $($installed.Version) in $($installed.Dir)" } else { 'installed: none' }
    if ($last) { "built from: $($last.commit.Substring(0,10)) $($last.subject) ($($last.ref), $($last.installedAt))" }
    else { 'built from: unknown (not installed by this script yet)' }
    exit 0
}

# --- 1. Worktree at the requested commit -------------------------------------------------------
Step "Fetching origin"
& git -C $main fetch --quiet origin
if ($LASTEXITCODE -ne 0) { throw 'git fetch origin failed' }
$commit = (& git -C $main rev-parse --verify "$Ref^{commit}" 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $commit) { throw "unknown ref: $Ref" }
$commit = $commit.Trim()
$subject = (& git -C $main log -1 --format=%s $commit).Trim()
Note "$Ref = $($commit.Substring(0,10)) $subject"

if (-not $Force -and $last -and $last.commit -eq $commit -and $installed) {
    Note "Already installed. Use -Force to rebuild anyway."
    if ($Launch -and -not (Get-RunningApp $installed.Dir)) { Start-Process -FilePath $installed.Exe }
    exit 0
}

if (-not (Test-Path -LiteralPath $wt)) {
    Step "Creating build worktree $wt"
    & git -C $main worktree add --quiet --detach $wt $commit
    if ($LASTEXITCODE -ne 0) { throw 'git worktree add failed' }
} else {
    Step "Moving build worktree to $($commit.Substring(0,10))"
    & git -C $wt checkout --quiet --force --detach $commit
    if ($LASTEXITCODE -ne 0) { throw 'git checkout failed in the build worktree' }
    & git -C $wt clean -fdq   # untracked files only; keeps ignored node_modules and target
}

# --- 2. Dependencies ---------------------------------------------------------------------------
$lock = Join-Path $wt 'src\package-lock.json'
$lockMark = Join-Path $wt 'src\node_modules\.install-main-lock'
$lockHash = (Get-FileHash -LiteralPath $lock -Algorithm SHA256).Hash
$haveHash = if (Test-Path -LiteralPath $lockMark) { (Get-Content -LiteralPath $lockMark -Raw).Trim() } else { '' }
if ($haveHash -ne $lockHash) {
    Step "npm ci (package-lock.json changed)"
    Push-Location (Join-Path $wt 'src')
    try {
        & npm.cmd ci --no-audit --no-fund   # .cmd: the npm.ps1 shim misparses args under -File
        if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
    } finally { Pop-Location }
    Set-Content -LiteralPath $lockMark -Value $lockHash -Encoding ascii
}

# --- 3. Build ----------------------------------------------------------------------------------
$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
foreach ($v in 'SHUSH_VAULT_PATH', 'WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS', 'WEBVIEW2_USER_DATA_FOLDER', 'CARGO_TARGET_DIR') {
    Remove-Item "Env:$v" -ErrorAction SilentlyContinue
}
$bundleDir = Join-Path $wt 'src-tauri\target\release\bundle\nsis'
if (Test-Path -LiteralPath $bundleDir) { Get-ChildItem -LiteralPath $bundleDir -Filter '*-setup.exe' | Remove-Item -Force }

Step "Building the release installer (first run is slow; later runs are incremental)"
$sw = [Diagnostics.Stopwatch]::StartNew()
$buildStart = Get-Date
# Build the frontend ourselves, then run the CLI from the repo root (where it finds src-tauri)
# with beforeBuildCommand disabled: from the root, its `npm run build` finds no package.json.
Push-Location (Join-Path $wt 'src')
try {
    & npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw 'frontend build failed' }
} finally { Pop-Location }
$cfg = Join-Path $state 'build-override.json'
Set-Content -LiteralPath $cfg -Value '{"build":{"beforeBuildCommand":""}}' -Encoding ascii
Push-Location $wt
try {
    & (Join-Path $wt 'src\node_modules\.bin\tauri.cmd') build --bundles nsis --config $cfg
    if ($LASTEXITCODE -ne 0) { throw 'tauri build failed' }
} finally { Pop-Location }
Note ("built in {0:mm\:ss}" -f $sw.Elapsed)

$setup = Get-ChildItem -LiteralPath $bundleDir -Filter '*-setup.exe' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $setup) { throw "no installer in $bundleDir" }
Note $setup.FullName

# --- 4. Close the running app ------------------------------------------------------------------
$running = Get-RunningApp $(if ($installed) { $installed.Dir } else { $null })
if ($running.Count -gt 0) {
    if (-not $CloseApp) {
        Write-Host ''
        Write-Host 'shush is running. Quit it (tray icon > Quit), then run this again,' -ForegroundColor Yellow
        Write-Host 'or pass -CloseApp to have the script close it. The build is kept, so the rerun is quick.' -ForegroundColor Yellow
        exit 2
    }
    Step "Closing shush"
    foreach ($p in $running) { [void]$p.CloseMainWindow() }
    $deadline = (Get-Date).AddSeconds(5)
    while ((Get-RunningApp $installed.Dir).Count -gt 0 -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
    # shush minimizes to the tray, so closing the window is usually not enough.
    Get-RunningApp $installed.Dir | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

# --- 5. Back up vault files --------------------------------------------------------------------
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = Join-Path $state "backups\$stamp"
$appData = Join-Path $env:APPDATA 'com.shush.vault'
$files = New-Object System.Collections.Generic.List[string]
if (Test-Path -LiteralPath $appData) {
    Get-ChildItem -LiteralPath $appData -File | ForEach-Object { $files.Add($_.FullName) }
    $list = Join-Path $appData 'vaults.json'
    if (Test-Path -LiteralPath $list) {
        # Pick every string that is an existing *.shush path, whatever the list's exact schema is.
        $raw = Get-Content -LiteralPath $list -Raw
        foreach ($m in [regex]::Matches($raw, '"((?:[^"\\]|\\.)*?\.shush)"')) {
            try { $p = ($m.Groups[1].Value | ForEach-Object { [regex]::Unescape($_) }) } catch { continue }
            if ((Test-Path -LiteralPath $p -PathType Leaf) -and -not $files.Contains($p)) { $files.Add($p) }
        }
    }
}
if ($files.Count -gt 0) {
    Step "Backing up $($files.Count) vault file(s) to $backup"
    New-Item -ItemType Directory -Force -Path $backup | Out-Null
    $i = 0
    foreach ($f in $files) {
        $i++
        $name = if ($f.StartsWith($appData, [StringComparison]::OrdinalIgnoreCase)) { Split-Path $f -Leaf } else { "external-$i-$(Split-Path $f -Leaf)" }
        Copy-Item -LiteralPath $f -Destination (Join-Path $backup $name)
    }
    # Record where external vaults came from, so a restore knows where to put them back.
    $files | Set-Content -LiteralPath (Join-Path $backup 'sources.txt') -Encoding utf8
    Get-ChildItem -LiteralPath (Join-Path $state 'backups') -Directory | Sort-Object Name -Descending |
        Select-Object -Skip 10 | Remove-Item -Recurse -Force
}

# --- 6. Install --------------------------------------------------------------------------------
Step "Installing $($setup.Name) silently"
$proc = Start-Process -FilePath $setup.FullName -ArgumentList '/S' -Wait -PassThru
if ($proc.ExitCode -ne 0) { throw "installer exited with code $($proc.ExitCode)" }
$after = Get-Installed
if (-not $after -or -not (Test-Path -LiteralPath $after.Exe)) { throw 'installer finished but shush.exe is missing' }
# (Tauri rewrites target\release\shush.exe after bundling, so compare times, not hashes.)
if ((Get-Item -LiteralPath $after.Exe).LastWriteTime -lt $buildStart) {
    throw "shush.exe in $($after.Dir) is older than this build: the installer did not replace it (app still running?)"
}
# A local GNU-toolchain build has no CFG/CET (MSVC-only); CI's release build does. Warn only.
$hc = Start-Process -FilePath powershell -WindowStyle Hidden -Wait -PassThru -ArgumentList @(
    '-NoProfile', '-File', "`"$(Join-Path $wt '.github\scripts\check-pe-hardening.ps1')`"", "`"$($after.Exe)`"")
if ($hc.ExitCode -ne 0) {
    Note 'note: PE hardening check failed (expected without MSVC: no CFG/CET). Fine for trying changes; releases come from CI.'
}

[pscustomobject]@{
    commit      = $commit
    subject     = $subject
    ref         = $Ref
    version     = $after.Version
    installer   = $setup.FullName
    backup      = $(if ($files.Count -gt 0) { $backup } else { $null })
    installedAt = (Get-Date).ToString('s')
} | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding utf8

Write-Host ''
Write-Host "Installed shush $($after.Version) from $($commit.Substring(0,10)) $subject" -ForegroundColor Green
Note "app:    $($after.Exe)"
if ($files.Count -gt 0) { Note "backup: $backup" }

if ($Launch) { Start-Process -FilePath $after.Exe }
