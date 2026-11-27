# Asserts Get-SensitivePaths still flags known security-relevant files (catches a refactor of
# Policy.ps1 that drops an entry) and does not flag plain code. Exit 0 ok, 1 on any miss.
# Keep one sample path per $SensitivePrefixes entry: the list here is independent of Policy.ps1
# on purpose, so dropping an entry there fails here.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')

$mustBeSensitive = @(
    'src-tauri/src/crypto/kdf.rs', 'src-tauri/src/vault/container.rs', 'src-tauri/src/update/client.rs',
    'src-tauri/src/bridge/mod.rs', 'src-tauri/src/sync/mod.rs', 'src-tauri/src/bin/shush-host.rs',
    'src-tauri/src/os/memory.rs', 'src-tauri/src/os/clipboard.rs', 'src-tauri/src/os/pipe.rs',
    'src-tauri/src/os/native_host.rs', 'src-tauri/src/os/session.rs', 'src-tauri/src/os/private_dir.rs',
    'src-tauri/src/os/win_hello.rs', 'src-tauri/src/totp/mod.rs',
    'src-tauri/src/os/ancestry.rs', 'src-tauri/src/os/replace.rs', 'src-tauri/src/os/recycle.rs',
    'src-tauri/src/net.rs',
    'src-tauri/Cargo.toml', 'src-tauri/Cargo.lock', 'src-tauri/tauri.conf.json', 'src-tauri/build.rs',
    'src-tauri/capabilities/default.json', 'src-tauri/permissions/x.toml', 'src-tauri/windows/hooks.nsh',
    'src-tauri/windows-app-manifest.xml',
    'src/package.json', 'src/package-lock.json', 'extension/manifest.json',
    '.github/workflows/ci.yml', '.claude/scripts/Policy.ps1', '.agents/skills/issue/SKILL.md',
    '.cargo/config.toml', 'scripts/release.ps1',
    'docs/spec/crypto.md', 'docs/FORMAT.md', 'docs/testing/README.md',
    'SECURITY.md', 'CLAUDE.md', 'GEMINI.md', 'AGENTS.md', 'release-please-config.json',
    '.release-please-manifest.json'
)
# lib.rs is listed on purpose: it is left out of $SensitivePrefixes by a recorded decision, so
# changing that decision must also update the comment beside the list and this line.
$mustBeRoutine = @('src/lib/App.svelte', 'README.md', 'src-tauri/src/lib.rs')

# Every src-tauri/src/os/*.rs must be sensitive or named here as routine, so a new OS module
# (the gap #285 fixed by hand) fails this check until someone decides which it is.
$routineOsFiles = @('mod.rs', 'browsers.rs', 'win_context.rs')

$bad = @()
foreach ($p in $mustBeSensitive) { if (@(Get-SensitivePaths @($p)).Count -ne 1) { $bad += "not sensitive: $p" } }
foreach ($p in $mustBeRoutine) { if (@(Get-SensitivePaths @($p)).Count -ne 0) { $bad += "unexpectedly sensitive: $p" } }
$osDir = Join-Path $PSScriptRoot '..\..\src-tauri\src\os'
if (Test-Path $osDir) {
    foreach ($f in @(Get-ChildItem $osDir -Filter *.rs -File | ForEach-Object Name)) {
        if ($routineOsFiles -contains $f) { continue }
        if (@(Get-SensitivePaths @("src-tauri/src/os/$f")).Count -ne 1) {
            $bad += "src-tauri/src/os/$f is neither in `$SensitivePrefixes nor in `$routineOsFiles here"
        }
    }
} else { $bad += "missing $osDir" }
if ($bad.Count) { $bad | ForEach-Object { Write-Output "policy-selfcheck: $_" }; exit 1 }
Write-Output 'policy-selfcheck: ok'
exit 0
