param(
  [Parameter(Mandatory)] [string] $Installer,
  [Parameter(Mandatory)] [string] $Out
)
# Usage (from the repo root; see docs/testing/README.md, "Installer"):
#   npx --prefix src tauri build --bundles nsis --config '{"productName":"shush-qa","identifier":"com.shush.qa","mainBinaryName":"shush-qa"}'
#   powershell -File docs/testing/installer/installer-e2e.ps1 `
#     -Installer src-tauri/target/release/bundle/nsis/shush-qa_<version>_x64-setup.exe -Out $env:TEMP/shush-installer-e2e
#
# End-to-end test of the NSIS installer/uninstaller using a QA-renamed build (product "shush-qa",
# identifier "com.shush.qa") so the owner's real shush install and vault are never touched.
# Pure Win32: windows are found with EnumWindows (title must contain "shush-qa"), controls with
# EnumChildWindows, and buttons are pressed by posting WM_COMMAND/BN_CLICKED to their dialog.
# No keyboard/mouse input is injected; screenshots are PrintWindow captures of those dialogs only.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class W32 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumChildWindows(IntPtr p, EnumProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern IntPtr SendMessageTimeout(IntPtr h, uint m, IntPtr w, StringBuilder l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] static extern IntPtr SendMessageTimeout(IntPtr h, uint m, IntPtr w, IntPtr l, uint f, uint t, out IntPtr r);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetWindowLong(IntPtr h, int i);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint f);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L, T, R, B; }

  public static IntPtr Send(IntPtr h, uint m, IntPtr w, IntPtr l) {
    IntPtr r; SendMessageTimeout(h, m, w, l, 2 /*ABORTIFHUNG*/, 5000, out r); return r;
  }
  public static string Text(IntPtr h) {
    IntPtr n; SendMessageTimeout(h, 0x000E, IntPtr.Zero, IntPtr.Zero, 2, 5000, out n);
    var sb = new StringBuilder((int)n + 1); IntPtr r;
    SendMessageTimeout(h, 0x000D, (IntPtr)((int)n + 1), sb, 2, 5000, out r);
    return sb.ToString();
  }
  public static string Class(IntPtr h) { var sb = new StringBuilder(256); GetClassName(h, sb, 256); return sb.ToString(); }
  public static List<IntPtr> TopLevel(string needle) {
    var f = new List<IntPtr>();
    EnumWindows((h, l) => { if (IsWindowVisible(h) && Text(h).Contains(needle)) f.Add(h); return true; }, IntPtr.Zero);
    return f;
  }
  public static List<IntPtr> Children(IntPtr p) {
    var f = new List<IntPtr>();
    EnumChildWindows(p, (h, l) => { f.Add(h); return true; }, IntPtr.Zero);
    return f;
  }
  // What a real click delivers: WM_COMMAND(BN_CLICKED, id) to the button's dialog.
  public static bool Click(IntPtr btn) {
    return PostMessage(GetParent(btn), 0x0111, (IntPtr)(GetDlgCtrlID(btn) & 0xFFFF), btn);
  }
}
'@

$P = 'shush-qa'; $ID = 'com.shush.qa'
$InstDir = Join-Path $env:LOCALAPPDATA $P
$Roam = Join-Path $env:APPDATA $ID
$Local = Join-Path $env:LOCALAPPDATA $ID
$Vault = Join-Path $Roam 'vault.shush'
$UninstKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$P"
$WerKey = 'HKCU:\Software\Microsoft\Windows\Windows Error Reporting\ExcludedApplications'
$StartLnk = Join-Path ([Environment]::GetFolderPath('Programs')) "$P.lnk"
$DeskLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) "$P.lnk"
New-Item -ItemType Directory -Force $Out | Out-Null
$results = [System.Collections.Generic.List[object]]::new()
$shot = 0

function Check($name, [bool]$ok, $detail = '') {
  $results.Add([pscustomobject]@{ Check = $name; Pass = $ok; Detail = "$detail" })
  Write-Host ("[{0}] {1} {2}" -f ($(if ($ok) { 'PASS' } else { 'FAIL' })), $name, $detail)
}

function Title($h) { [W32]::Text($h) }
function Texts($h) { (@([W32]::Children($h)) | ForEach-Object { [W32]::Text($_) }) -join "`n" }

function Wait-Window([scriptblock]$Match, [int]$Timeout = 180) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $Timeout) {
    foreach ($h in [W32]::TopLevel($P)) { if (& $Match $h) { return $h } }
    Start-Sleep -Milliseconds 300
  }
  $seen = (@([W32]::TopLevel($P)) | ForEach-Object { "[$(Title $_)]" }) -join '; '
  throw "Timed out after $([int]$sw.Elapsed.TotalSeconds)s waiting for window $Match; shush-qa windows: $seen"
}

function Wait-Text($h, $regex, [int]$Timeout = 180) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $Timeout) {
    $t = Texts $h
    if ($t -match $regex) { return $t }
    Start-Sleep -Milliseconds 300
  }
  throw "Timed out waiting for /$regex/ in '$(Title $h)'"
}

function Find-Ctl($h, $class, $regex) {
  @([W32]::Children($h)) | Where-Object { [W32]::Class($_) -like $class -and ([W32]::Text($_) -replace '&', '') -match $regex } |
    Select-Object -First 1
}

function Press($h, $regex) {
  $b = Find-Ctl $h 'Button' $regex
  if (-not $b) { throw "Button /$regex/ not found in '$(Title $h)'" }
  if (-not [W32]::IsWindowEnabled($b)) { throw "Button /$regex/ disabled" }
  [W32]::Click($b) | Out-Null
  Start-Sleep -Milliseconds 900
}

function Box-On($b) { [int][W32]::Send($b, 0x00F0, [IntPtr]::Zero, [IntPtr]::Zero) -eq 1 }  # BM_GETCHECK
function Set-Box($h, $regex, [bool]$on) {
  $b = Find-Ctl $h 'Button' $regex
  if (-not $b) { throw "Checkbox /$regex/ not found" }
  [W32]::Send($b, 0x00F1, [IntPtr]([int]$on), [IntPtr]::Zero) | Out-Null  # BM_SETCHECK
  Box-On $b
}

function Advance-Until($h, $regex, [int]$Timeout = 180) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $Timeout) {
    $t = Texts $h
    if ($t -match $regex) { return $t }
    $b = Find-Ctl $h 'Button' '^(Next >|Install|I Agree)$'
    if ($b -and [W32]::IsWindowEnabled($b)) { [W32]::Click($b) | Out-Null; Start-Sleep -Milliseconds 1200 }
    else { Start-Sleep -Milliseconds 500 }
  }
  throw "Advance-Until timed out waiting for /$regex/"
}

function Snap($h, $label) {
  $script:shot++
  $r = New-Object W32+RECT; [W32]::GetWindowRect($h, [ref]$r) | Out-Null
  $bmp = New-Object System.Drawing.Bitmap ([Math]::Max(1, $r.R - $r.L)), ([Math]::Max(1, $r.B - $r.T))
  $g = [System.Drawing.Graphics]::FromImage($bmp); $hdc = $g.GetHdc()
  [W32]::PrintWindow($h, $hdc, 2) | Out-Null
  $g.ReleaseHdc($hdc); $g.Dispose()
  $f = Join-Path $Out ('{0:D2}-{1}.png' -f $script:shot, $label)
  $bmp.Save($f); $bmp.Dispose()
}

function QaApp { @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path.StartsWith($InstDir, 'OrdinalIgnoreCase') }) }
function Stop-QaApp { QaApp | ForEach-Object { Stop-Process -Id $_.Id -Force -Confirm:$false }; Start-Sleep 1 }

function Plant-Vault {
  New-Item -ItemType Directory -Force $Roam | Out-Null
  $bytes = New-Object byte[] 4096; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  [IO.File]::WriteAllBytes($Vault, $bytes)
}

function Wait-Gone([scriptblock]$Cond, [int]$Timeout = 60) {
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($sw.Elapsed.TotalSeconds -lt $Timeout -and -not (& $Cond)) { Start-Sleep -Milliseconds 500 }
}

function Gui-Uninstall([bool]$deleteData, [string]$answer, [string]$tag) {
  Start-Process (Join-Path $InstDir 'uninstall.exe') | Out-Null
  $w = Wait-Window { param($x) (Title $x) -match 'Uninstall' }
  $null = Wait-Text $w 'Delete the application data'
  $on = Set-Box $w 'Delete the application data' $deleteData
  Check "$tag : delete-data checkbox set to $deleteData" ($on -eq $deleteData)
  Snap $w "$tag-uninstall-confirm"
  Press $w '^Uninstall$'
  if ($answer) {
    $mb = Wait-Window { param($x) (Texts $x) -match 'permanently erases' } 60
    $t = Texts $mb
    Check "$tag : vault warning dialog shown" ($t -match 'permanently erases')
    Check "$tag : warning names the data folder" ($t -match [regex]::Escape($Roam)) $Roam
    $no = Find-Ctl $mb 'Button' '^No$'
    Check "$tag : 'No' is the default button" ($no -and (([W32]::GetWindowLong($no, -16) -band 0xF) -eq 1))  # BS_DEFPUSHBUTTON
    Snap $mb "$tag-vault-warning"
    Press $mb "^$answer$"
  } else {
    Start-Sleep 3
    $mb = @([W32]::TopLevel($P) | Where-Object { (Texts $_) -match 'permanently erases' })
    Check "$tag : no vault warning when box unticked" ($mb.Count -eq 0)
  }
  $null = Wait-Text $w 'Completed|Uninstallation Complete' 120
  Snap $w "$tag-uninstall-done"
  if (Find-Ctl $w 'Button' '^Close$') { Press $w '^Close$' }
  Wait-Gone { -not [W32]::IsWindow($w) } 30
  Start-Sleep 2
}

function Assert-Uninstalled($tag) {
  Check "$tag : app files removed" (-not (Test-Path (Join-Path $InstDir "$P.exe")))
  Check "$tag : Apps & features entry removed" (-not (Test-Path $UninstKey))
  Check "$tag : Start Menu shortcut removed" (-not (Test-Path $StartLnk))
  Check "$tag : desktop shortcut removed" (-not (Test-Path $DeskLnk))
  $wer = (Get-ItemProperty $WerKey -ErrorAction SilentlyContinue)."$P.exe"
  Check "$tag : WER exclusion value removed (#60)" ($null -eq $wer)
}

function Silent-Install {
  $p = Start-Process $Installer -ArgumentList '/S' -PassThru -Wait
  Check "silent install exit code 0" ($p.ExitCode -eq 0) "exit=$($p.ExitCode)"
  Stop-QaApp
}

function Silent-Uninstall {
  Start-Process (Join-Path $InstDir 'uninstall.exe') -ArgumentList '/S' | Out-Null
  # the stub relaunches itself from %TEMP%, so wait for the effect, not the process
  Wait-Gone { -not (Test-Path $UninstKey) } 90
  Start-Sleep 2
}

function Seed-Wer {
  if (-not (Test-Path $WerKey)) { New-Item $WerKey -Force | Out-Null }
  New-ItemProperty $WerKey -Name "$P.exe" -Value 1 -PropertyType DWord -Force | Out-Null
}

# ---------- Preconditions ----------
Check 'precondition: QA product not installed' (-not (Test-Path $UninstKey))
Check 'precondition: QA app data absent' (-not (Test-Path $Roam))

try {
  # ---------- T1: interactive first install ----------
  Start-Process $Installer | Out-Null
  $w = Wait-Window { param($x) (Title $x) -match 'Setup' }
  $null = Wait-Text $w 'Welcome to'
  Snap $w 'T1-welcome'
  Press $w '^Next'
  $t = Wait-Text $w 'License Agreement'
  $lic = @([W32]::Children($w)) | Where-Object { [W32]::Class($_) -like 'RichEdit*' } | Select-Object -First 1
  $licText = if ($lic) { [W32]::Text($lic) } else { '' }
  Check 'T1: license page shown' $true
  Check 'T1: license page shows the MIT text' ($licText -match 'MIT License' -and $licText -match 'Permission is hereby granted') (($licText -split "`n")[0])
  Snap $w 'T1-license'
  Press $w 'I Agree'
  $null = Wait-Text $w 'Choose Install Location'
  $dest = [W32]::Text((Find-Ctl $w 'Edit' '.*'))
  Check 'T1: default folder is per-user %LOCALAPPDATA%\shush-qa' ($dest.TrimEnd('\') -ieq $InstDir) $dest
  Snap $w 'T1-directory'
  $t = Advance-Until $w 'Installation Complete|Completing'
  if ($t -match 'Installation Complete' -and $t -notmatch 'Completing') { Snap $w 'T1-installed'; $t = Advance-Until $w 'Completing' }
  $desk = Find-Ctl $w 'Button' 'desktop shortcut'
  $run = Find-Ctl $w 'Button' '^Run '
  Check 'T1: finish page offers "Create desktop shortcut"' ($null -ne $desk)
  Check 'T1: finish page offers "Run shush-qa"' ($null -ne $run)
  Check 'T1: "Run" ticked by default' ($run -and (Box-On $run))
  Check 'T1: "Create desktop shortcut" ticked by default' ($desk -and (Box-On $desk))
  Snap $w 'T1-finish'
  Press $w '^Finish$'
  Wait-Gone { (QaApp).Count -gt 0 } 30
  Start-Sleep 5

  Check 'T1: app installed to %LOCALAPPDATA%\shush-qa' (Test-Path (Join-Path $InstDir "$P.exe"))
  Check 'T1: uninstaller present' (Test-Path (Join-Path $InstDir 'uninstall.exe'))
  $u = Get-ItemProperty $UninstKey -ErrorAction SilentlyContinue
  Check 'T1: Apps & features entry (per-user, HKCU)' ($null -ne $u) "$($u.DisplayName) $($u.DisplayVersion) / $($u.Publisher)"
  Check 'T1: no machine-wide (HKLM) entry' (-not (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$P"))
  Check 'T1: Start Menu shortcut created' (Test-Path $StartLnk) $StartLnk
  Check 'T1: desktop shortcut created' (Test-Path $DeskLnk) $DeskLnk
  $app = QaApp
  Check 'T1: "Run" launched the app' ($app.Count -gt 0) ("pids=" + ($app.Id -join ','))
  $main = @($app | ForEach-Object { $_.Refresh(); $_.MainWindowHandle } | Where-Object { $_ -ne [IntPtr]::Zero }) | Select-Object -First 1
  if ($main) { Snap $main 'T1-app-window-capture-protected' }
  $wer = (Get-ItemProperty $WerKey -ErrorAction SilentlyContinue)."$P.exe"
  Check 'T1: running app registered its WER exclusion' ($wer -eq 1) "value=$wer"

  # ---------- T1b: uninstall while the app is running ----------
  Start-Process (Join-Path $InstDir 'uninstall.exe') | Out-Null
  $w = Wait-Window { param($x) (Title $x) -match 'Uninstall' }
  $null = Wait-Text $w 'Delete the application data'
  Press $w '^Uninstall$'
  $run = Wait-Window { param($x) (Texts $x) -match 'is running' } 60
  Check 'T1b: uninstaller detects the running app and asks to close it' $true ((Texts $run) -split "`n" | Where-Object { $_ -match 'running' } | Select-Object -First 1)
  Snap $run 'T1b-app-running-prompt'
  Press $run '^Cancel$'
  Start-Sleep 3
  Check 'T1b: cancelling leaves the install intact' ((Test-Path $UninstKey) -and (Test-Path (Join-Path $InstDir "$P.exe")))
  foreach ($h in [W32]::TopLevel($P)) {
    if ((Title $h) -match 'Uninstall') {
      Snap $h 'T1b-uninstall-aborted'
      $c = @(Find-Ctl $h 'Button' '^Close$'; Find-Ctl $h 'Button' '^Cancel$') | Where-Object { $_ -and [W32]::IsWindowEnabled($_) } | Select-Object -First 1
      Check 'T1b: aborted uninstall can be dismissed' ($null -ne $c)
      if ($c) { [W32]::Click($c) | Out-Null; Start-Sleep 1 }
    }
  }
  Wait-Gone { @([W32]::TopLevel($P) | Where-Object { (Title $_) -match 'Uninstall' }).Count -eq 0 } 20
  Stop-QaApp

  # ---------- T2: reinstall over an existing install keeps data ----------
  Plant-Vault
  $before = (Get-FileHash $Vault).Hash
  Start-Process $Installer | Out-Null
  $w = Wait-Window { param($x) (Title $x) -match 'Setup' }
  $t = Advance-Until $w 'Already Installed|already installed'
  Snap $w 'T2-already-installed'
  Check 'T2: setup detects the existing install' $true
  $t = Advance-Until $w 'Completing'
  $null = Set-Box $w '^Run ' $false
  Snap $w 'T2-finish'
  Press $w '^Finish$'
  Start-Sleep 2
  Check 'T2: vault untouched by reinstall' ((Get-FileHash $Vault).Hash -eq $before)
  Stop-QaApp

  # ---------- T3: box ticked, answer No -> vault kept ----------
  Seed-Wer
  Gui-Uninstall $true 'No' 'T3'
  Assert-Uninstalled 'T3'
  Check 'T3: vault KEPT after declining' ((Test-Path $Vault) -and (Get-FileHash $Vault).Hash -eq $before)

  # ---------- T4: box unticked -> no prompt, vault kept ----------
  Silent-Install; Seed-Wer
  Gui-Uninstall $false $null 'T4'
  Assert-Uninstalled 'T4'
  Check 'T4: vault kept (box unticked)' (Test-Path $Vault)

  # ---------- T5: silent install/uninstall keep vault ----------
  Silent-Install
  Check 'T5: silent install registered' (Test-Path $UninstKey)
  Check 'T5: silent install creates Start Menu shortcut' (Test-Path $StartLnk)
  Seed-Wer
  Silent-Uninstall
  Assert-Uninstalled 'T5'
  Check 'T5: vault kept on silent uninstall' (Test-Path $Vault)

  # ---------- T6: box ticked, answer Yes -> data deleted ----------
  Silent-Install; Seed-Wer
  New-Item -ItemType Directory -Force $Local | Out-Null
  Gui-Uninstall $true 'Yes' 'T6'
  Assert-Uninstalled 'T6'
  Check 'T6: %APPDATA%\com.shush.qa deleted after confirming' (-not (Test-Path $Roam))
  Check 'T6: %LOCALAPPDATA%\com.shush.qa deleted after confirming' (-not (Test-Path $Local))
}
catch {
  Check 'harness: unexpected error' $false $_.Exception.Message
  foreach ($h in [W32]::TopLevel($P)) { try { Snap $h 'error-state' } catch {} }
}
finally {
  Stop-QaApp
  $results | ConvertTo-Json | Set-Content (Join-Path $Out 'results.json') -Encoding utf8
  $f = @($results | Where-Object { -not $_.Pass }).Count
  Write-Host "`n$($results.Count - $f)/$($results.Count) checks passed"
}
