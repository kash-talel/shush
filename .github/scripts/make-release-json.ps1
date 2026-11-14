# Writes release.json (feed schema 1, see src-tauri/src/update/mod.rs) for one installer.
param(
  [Parameter(Mandatory)][string]$Version,
  [Parameter(Mandatory)][string]$Channel,
  [Parameter(Mandatory)][string]$Installer,
  [Parameter(Mandatory)][string]$Url,
  [Parameter(Mandatory)][string]$NotesUrl,
  [Parameter(Mandatory)][string]$Out,
  [string]$MinSupported = '',
  [switch]$Security
)
$ErrorActionPreference = 'Stop'
$file = Get-Item -LiteralPath $Installer
$doc = [ordered]@{
  schema      = 1
  channel     = $Channel
  version     = $Version
  released_at = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
  security    = [bool]$Security
  artifact    = [ordered]@{
    target = 'windows-x86_64-nsis'
    url    = $Url
    sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLower()
    size   = [int64]$file.Length
  }
  notes_url   = $NotesUrl
}
if ($MinSupported) { $doc['min_supported'] = $MinSupported }
# No BOM, LF only: these exact bytes are hashed and signed.
$json = ($doc | ConvertTo-Json -Depth 5) -replace "`r`n", "`n"
[IO.File]::WriteAllText((Join-Path (Get-Location) $Out), $json + "`n", (New-Object Text.UTF8Encoding $false))
