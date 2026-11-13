# Per-checkout build and E2E environment. DOT-SOURCE it at the start of every PowerShell
# command that builds, tests or launches the app:
#
#     . .claude/scripts/issue-env.ps1; cargo test --manifest-path src-tauri/Cargo.toml
#
# Sets, for the current checkout only:
#   PATH                                   cargo on PATH
#   CDP_PORT                               9222 in the main checkout; 10000 + (N % 10000) in the
#                                          worktree for issue N, so parallel runs never share a port
#   WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS  CDP on that port, localhost only
#   SHUSH_VAULT_PATH                       scratch vault under this checkout's src-tauri/target/e2e.
#                                          Debug builds derive their WebView2 profile and
#                                          single-instance key from it (#56), so those are
#                                          isolated per checkout too.
# The docs/testing CDP drivers already read CDP_PORT.

$__top = (& git rev-parse --show-toplevel 2>$null)
if (-not $__top) { throw 'issue-env: run from inside the shush repository' }
$__top = [IO.Path]::GetFullPath($__top.Trim())
$__common = [IO.Path]::GetFullPath((& git rev-parse --path-format=absolute --git-common-dir).Trim())
$__isMain = ((Split-Path $__common -Parent).TrimEnd('\') -ieq $__top.TrimEnd('\'))

if ($__isMain) {
    $__port = 9222
} else {
    $__n = 0
    $__branch = (& git rev-parse --abbrev-ref HEAD 2>$null)
    if ("$__branch" -match 'issue-(\d+)') { $__n = [int]$Matches[1] }
    elseif ((Split-Path $__top -Leaf) -match '^issue-(\d+)$') { $__n = [int]$Matches[1] }
    if ($__n -gt 0) {
        $__port = 10000 + ($__n % 10000)
    } else {
        # Not tied to an issue: a stable port from the path (20000-29999).
        $__h = [BitConverter]::ToUInt16([Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($__top.ToLowerInvariant())), 0)
        $__port = 20000 + ($__h % 10000)
    }
}

$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
$env:CDP_PORT = "$__port"
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = "--remote-debugging-port=$__port --remote-debugging-address=127.0.0.1"
$__scratch = Join-Path $__top 'src-tauri\target\e2e'
if (-not (Test-Path -LiteralPath $__scratch)) { New-Item -ItemType Directory -Force -Path $__scratch | Out-Null }
$env:SHUSH_VAULT_PATH = Join-Path $__scratch 'vault.shush'

Remove-Variable __top, __common, __isMain, __port, __n, __branch, __h, __scratch -ErrorAction SilentlyContinue
