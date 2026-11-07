# Usage: dialog.ps1 -Title "Select keyfile" -Path "C:\long\path\file"
# Fills a common file dialog's filename box and presses Open using window
# messages only (no keyboard focus required, nothing can leak to other apps).
param([string]$Title, [string]$Path)
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class D {
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindow(string c, string t);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr FindWindowEx(IntPtr p, IntPtr a, string c, string t);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, string l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h, int id);
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  static string Cls(IntPtr h) { var b = new StringBuilder(64); GetClassName(h, b, 64); return b.ToString(); }
  // First Edit whose parent is a ComboBox: the filename box in both Open and Save dialogs.
  public static IntPtr FileNameEdit(IntPtr dlg) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(dlg, (h, l) => { if (Cls(h) == "Edit" && Cls(GetParent(h)) == "ComboBox") { found = h; return false; } return true; }, IntPtr.Zero);
    return found;
  }
}
"@
$dlg = [D]::FindWindow("#32770", $Title)
if ($dlg -eq [IntPtr]::Zero) { throw "dialog '$Title' not found" }
# Filename box: ComboBoxEx32 > ComboBox > Edit (control id 1148 = cmb13).
$edit = [D]::FileNameEdit($dlg)
if ($edit -eq [IntPtr]::Zero) { throw "filename edit control not found" }
[void][D]::SendMessage($edit, 0x000C, [IntPtr]::Zero, $Path)          # WM_SETTEXT
$ok = [D]::GetDlgItem($dlg, 1)                                          # IDOK = Open
[void][D]::SendMessage($ok, 0x00F5, [IntPtr]::Zero, [IntPtr]::Zero)     # BM_CLICK
"submitted '$Path'"
