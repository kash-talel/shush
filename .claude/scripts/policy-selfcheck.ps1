# Asserts Get-SensitivePaths still flags known security-relevant files (catches a refactor of
# Policy.ps1 that drops an entry) and does not flag plain code. Exit 0 ok, 1 on any miss.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Policy.ps1')

$mustBeSensitive = @(
    'src-tauri/src/crypto/kdf.rs', 'src-tauri/src/vault/container.rs', 'src-tauri/src/update/client.rs',
    'src-tauri/src/bridge/mod.rs', 'src-tauri/src/sync/mod.rs', 'src-tauri/src/bin/shush-host.rs',
    'src-tauri/src/os/memory.rs', 'src-tauri/src/os/clipboard.rs', 'src-tauri/src/os/pipe.rs',
    'src-tauri/src/os/native_host.rs', 'src-tauri/src/os/session.rs', 'src-tauri/src/os/private_dir.rs',
    'src-tauri/src/os/win_hello.rs', 'src-tauri/src/totp/mod.rs', 'src-tauri/src/net.rs',
    'src-tauri/src/os/ancestry.rs', 'src-tauri/src/os/replace.rs', 'src-tauri/src/os/recycle.rs',
    'src-tauri/Cargo.toml', 'extension/manifest.json', '.github/workflows/ci.yml',
    '.claude/scripts/Policy.ps1', 'docs/spec/crypto.md', 'docs/FORMAT.md', 'CLAUDE.md'
)
$mustBeRoutine = @('src/lib/App.svelte', 'README.md', 'src-tauri/src/lib.rs')

$bad = @()
foreach ($p in $mustBeSensitive) { if (@(Get-SensitivePaths @($p)).Count -ne 1) { $bad += "not sensitive: $p" } }
foreach ($p in $mustBeRoutine) { if (@(Get-SensitivePaths @($p)).Count -ne 0) { $bad += "unexpectedly sensitive: $p" } }
if ($bad.Count) { $bad | ForEach-Object { Write-Output "policy-selfcheck: $_" }; exit 1 }
Write-Output 'policy-selfcheck: ok'
exit 0
