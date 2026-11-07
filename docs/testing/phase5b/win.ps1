# Window-message helpers for the Phase 5 e2e (no keyboard/mouse input).
#   win.ps1 affinity          -> display affinity of the main shush window
#   win.ps1 visible           -> whether the main shush window is visible
#   win.ps1 post-lock         -> post WM_WTSSESSION_CHANGE/WTS_SESSION_LOCK to shush's event window
#   win.ps1 close             -> post WM_CLOSE to the main shush window
param([string]$Action)
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class W5 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool GetWindowDisplayAffinity(IntPtr h, out uint a);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string c, string t);
  [DllImport("user32.dll", SetLastError=true)] public static extern bool RegisterHotKey(IntPtr h, int id, uint m, uint vk);
  [DllImport("user32.dll")] public static extern bool UnregisterHotKey(IntPtr h, int id);
  public static IntPtr FindMain(uint[] pids) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p);
      var t = new StringBuilder(64); GetWindowText(h, t, 64); var c = new StringBuilder(64); GetClassName(h, c, 64);
      if (Array.IndexOf(pids, p) >= 0 && t.ToString() == "shush" && c.ToString() != "shush.session-events") { found = h; return false; }
      return true; }, IntPtr.Zero);
    return found;
  }
}
"@
$pids = [uint32[]](Get-Process shush -ErrorAction Stop | ForEach-Object { $_.Id })
$main = [W5]::FindMain($pids)
switch ($Action) {
  "affinity" { $a = 0; [void][W5]::GetWindowDisplayAffinity($main, [ref]$a); "0x{0:X}" -f $a }
  "visible"  { [W5]::IsWindowVisible($main) }
  "post-lock" {
    $ev = [W5]::FindWindow("shush.session-events", [NullString]::Value)
    if ($ev -eq [IntPtr]::Zero) { throw "event window not found" }
    [W5]::PostMessage($ev, 0x02B1, [IntPtr]7, [IntPtr]0)
  }
  "close" { [W5]::PostMessage($main, 0x0010, [IntPtr]0, [IntPtr]0) }
  "spot-visible" { [W5]::IsWindowVisible([W5]::FindWindow([NullString]::Value, "shush quick search")) }
  # Try to grab Ctrl+Alt+Space ourselves: 1409 = already registered by another process (shush).
  "hotkey-owned" {
    if ([W5]::RegisterHotKey([IntPtr]::Zero, 0x5A17, 0x3, 0x20)) { [void][W5]::UnregisterHotKey([IntPtr]::Zero, 0x5A17); "free" }
    else { [Runtime.InteropServices.Marshal]::GetLastWin32Error() }
  }
}
