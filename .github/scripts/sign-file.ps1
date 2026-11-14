# Signs a file with the key in TAURI_SIGNING_PRIVATE_KEY (+ _PASSWORD) and writes <file>.minisig
# containing plain minisign text, which is what the app's `minisign-verify` client expects.
# `tauri signer sign` writes <file>.sig, which is that text base64-encoded; decode it.
param([Parameter(Mandatory)][string]$File)
$ErrorActionPreference = 'Stop'
if (-not $env:TAURI_SIGNING_PRIVATE_KEY) { throw 'TAURI_SIGNING_PRIVATE_KEY is not set' }
npx --prefix src tauri signer sign $File
if ($LASTEXITCODE -ne 0) { throw 'tauri signer sign failed' }
$b64 = (Get-Content -LiteralPath "$File.sig" -Raw).Trim()
$text = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
[IO.File]::WriteAllText("$File.minisig", $text, (New-Object Text.UTF8Encoding $false))
Remove-Item -LiteralPath "$File.sig"
