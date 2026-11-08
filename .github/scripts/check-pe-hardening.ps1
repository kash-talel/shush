# Fails unless a Windows PE binary carries the exploit mitigations shush ships with (#74):
# ASLR (+ high-entropy), DEP, Control Flow Guard, CET shadow-stack compatibility, and an
# embedded manifest declaring asInvoker + Windows 10/11 supportedOS.
#   pwsh .github/scripts/check-pe-hardening.ps1 path\to\shush.exe
param([Parameter(Mandatory)] [string] $Path)
$ErrorActionPreference = 'Stop'

$b = [IO.File]::ReadAllBytes((Resolve-Path $Path))
function U16($o) { [BitConverter]::ToUInt16($b, $o) }
function U32($o) { [BitConverter]::ToUInt32($b, $o) }

$pe = U32 0x3c
if ((U32 $pe) -ne 0x00004550) { throw "$Path is not a PE file" }
$sections = U16 ($pe + 6)
$optSize = U16 ($pe + 20)
$opt = $pe + 24
if ((U16 $opt) -ne 0x20b) { throw 'Expected a PE32+ (64-bit) image' }
$dllChars = U16 ($opt + 70)

# Map an RVA to a file offset through the section table.
$secTable = $opt + $optSize
function RvaToOffset($rva) {
  for ($i = 0; $i -lt $sections; $i++) {
    $s = $secTable + 40 * $i
    $va = U32 ($s + 12); $rawSize = U32 ($s + 16); $raw = U32 ($s + 20); $vsize = U32 ($s + 8)
    if ($rva -ge $va -and $rva -lt $va + [Math]::Max($vsize, $rawSize)) { return $raw + ($rva - $va) }
  }
  return -1
}

# CET compatibility lives in an IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS (20) debug entry.
$cet = $false
$dbgRva = U32 ($opt + 112 + 6 * 8); $dbgSize = U32 ($opt + 112 + 6 * 8 + 4)
if ($dbgRva -ne 0) {
  $dbg = RvaToOffset $dbgRva
  for ($e = 0; $e -lt [Math]::Floor($dbgSize / 28); $e++) {
    $entry = $dbg + 28 * $e
    if ((U32 ($entry + 12)) -eq 20) { $cet = ((U32 (U32 ($entry + 24))) -band 0x1) -ne 0 }
  }
}

$text = [Text.Encoding]::UTF8.GetString($b)
$checks = [ordered]@{
  'ASLR (DYNAMIC_BASE)'          = ($dllChars -band 0x0040) -ne 0
  'High-entropy ASLR'            = ($dllChars -band 0x0020) -ne 0
  'DEP (NX_COMPAT)'              = ($dllChars -band 0x0100) -ne 0
  'Control Flow Guard (GUARD_CF)' = ($dllChars -band 0x4000) -ne 0
  'CET shadow-stack compatible'  = $cet
  'Manifest: asInvoker'          = $text.Contains('requestedExecutionLevel level="asInvoker"')
  'Manifest: Windows 10/11 supportedOS' = $text.Contains('8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a')
}
$failed = 0
foreach ($k in $checks.Keys) {
  $ok = $checks[$k]; if (-not $ok) { $failed++ }
  '{0} {1}' -f ($(if ($ok) { '[x]' } else { '[ ]' })), $k
}
if ($failed) { Write-Error "$failed hardening check(s) failed for $Path"; exit 1 }
"All hardening checks passed for $Path"
