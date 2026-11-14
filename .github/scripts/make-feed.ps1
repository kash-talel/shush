# Builds one channel of the update feed into <OutDir>/updates/<channel>/ from the newest matching
# release that is not yanked, then signs a fresh freshness.json with the timestamp key.
#   release.json + release.json.minisig  copied verbatim from the (immutable) release
#   latest.json                          Tauri-updater static manifest built from the installer .sig
#   freshness.json + .minisig            binds the exact release.json bytes to a 14-day window
param(
  [Parameter(Mandatory)][ValidateSet('stable', 'beta')][string]$Channel,
  [Parameter(Mandatory)][string]$Repo,
  [Parameter(Mandatory)][string]$OutDir
)
$ErrorActionPreference = 'Stop'
$yanked = @()
if (Test-Path .github/feed-yanked.txt) {
  $yanked = Get-Content .github/feed-yanked.txt | ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith('#') }
}
$wantPre = $Channel -eq 'beta'
$rels = gh api "repos/$Repo/releases?per_page=50" | ConvertFrom-Json
# Releases cut before the feed existed (v0.1.0, v0.1.1) carry no release.json; skip them rather
# than fail, or the whole Pages deploy (site included) would stop once the timestamp key is set.
$rel = $rels | Where-Object {
  -not $_.draft -and $_.tag_name -like 'v*' -and ([bool]$_.prerelease -eq $wantPre) -and
  (@($_.assets | Where-Object { $_.name -eq 'release.json' }).Count -gt 0) -and
  ($yanked -notcontains $_.tag_name.Substring(1)) -and ($yanked -notcontains $_.tag_name)
} | Select-Object -First 1
if (-not $rel) { Write-Host "No $Channel release yet; channel left out of the feed."; return }
$tag = $rel.tag_name
$ver = $tag.Substring(1)
$work = New-Item -ItemType Directory -Force (Join-Path ([IO.Path]::GetTempPath()) "feed-$Channel")
gh release download $tag -R $Repo -D $work.FullName -p release.json -p release.json.minisig -p "shush_${ver}_x64-setup.exe.sig" --clobber
if ($LASTEXITCODE -ne 0) { throw "Could not download feed files of $tag" }

$dest = New-Item -ItemType Directory -Force (Join-Path $OutDir "updates/$Channel")
$rj = Join-Path $work.FullName release.json
$release = Get-Content -LiteralPath $rj -Raw | ConvertFrom-Json
if ($release.version -ne $ver -or $release.channel -ne $Channel) {
  throw "release.json of $tag disagrees (version $($release.version), channel $($release.channel))"
}
Copy-Item $rj, (Join-Path $work.FullName release.json.minisig) $dest

$sig = (Get-Content -LiteralPath (Join-Path $work.FullName "shush_${ver}_x64-setup.exe.sig") -Raw).Trim()
$latest = [ordered]@{
  version   = $ver
  notes     = $release.notes_url
  pub_date  = $release.released_at
  platforms = [ordered]@{ 'windows-x86_64' = [ordered]@{ signature = $sig; url = $release.artifact.url } }
}
$utf8 = New-Object Text.UTF8Encoding $false
[IO.File]::WriteAllText((Join-Path $dest.FullName latest.json), (($latest | ConvertTo-Json -Depth 5) -replace "`r`n", "`n") + "`n", $utf8)

$now = [DateTime]::UtcNow
$fresh = [ordered]@{
  schema         = 1
  channel        = $Channel
  release_sha256 = (Get-FileHash -LiteralPath $rj -Algorithm SHA256).Hash.ToLower()
  issued_at      = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
  expires_at     = $now.AddDays(14).ToString('yyyy-MM-ddTHH:mm:ssZ')
}
$fp = Join-Path $dest.FullName freshness.json
[IO.File]::WriteAllText($fp, (($fresh | ConvertTo-Json) -replace "`r`n", "`n") + "`n", $utf8)
& "$PSScriptRoot/sign-file.ps1" $fp
Write-Host "Feed $Channel -> $tag (fresh until $($fresh.expires_at))"
