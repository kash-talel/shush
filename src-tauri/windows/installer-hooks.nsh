; shush NSIS installer hooks (wired up in tauri.conf.json > bundle.windows.nsis.installerHooks).
;
; Tauri's uninstaller offers a "Delete the application data" checkbox that runs
; `RmDir /r "$APPDATA\${BUNDLEID}"`. For shush that folder holds the default vault
; (%APPDATA%\com.shush.vault\vault.shush), its sidecars and the vault list, so one stray
; tick would destroy every password with no way back. Ask again, default to keeping the
; data, and keep it in silent mode (/S), where the checkbox is never shown anyway.
;
; $DeleteAppDataCheckboxState and $UpdateMode are variables of Tauri's installer.nsi
; template; this macro runs at the top of its `Section Uninstall`, before they are read.

!macro NSIS_HOOK_PREUNINSTALL
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    Push $R0
    ReadEnvStr $R0 APPDATA
    MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 \
      "You chose to delete the application data.$\r$\n$\r$\nThis permanently erases your shush vault and settings in:$\r$\n$R0\${BUNDLEID}$\r$\n$\r$\nPasswords in it cannot be recovered without an encrypted backup (.shushbackup). Vaults you saved in other folders are not touched.$\r$\n$\r$\nDelete the vault?$\r$\n$\r$\nYes: delete it.  No: keep it and only uninstall the app." \
      /SD IDNO IDYES shush_delete_confirmed
      StrCpy $DeleteAppDataCheckboxState 0
    shush_delete_confirmed:
    Pop $R0
  ${EndIf}
!macroend

; At startup shush calls WerAddExcludedApplication("shush.exe") so crash dumps never carry
; vault memory (#6). That writes a per-user value which outlives the app (#60): remove it on a
; real uninstall, but not on an update, where the new build re-adds it on first launch anyway.
!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
    DeleteRegValue HKCU "Software\Microsoft\Windows\Windows Error Reporting\ExcludedApplications" "${MAINBINARYNAME}.exe"
    DeleteRegKey /ifempty HKCU "Software\Microsoft\Windows\Windows Error Reporting\ExcludedApplications"
    ; Browser native-messaging registration written by Settings > Pair browser (#53). Their
    ; manifests live in the app data folder, which the uninstaller keeps or deletes as asked.
    DeleteRegKey HKCU "Software\Google\Chrome\NativeMessagingHosts\com.shush.vault"
    DeleteRegKey HKCU "Software\Microsoft\Edge\NativeMessagingHosts\com.shush.vault"
    DeleteRegKey HKCU "Software\Mozilla\NativeMessagingHosts\com.shush.vault"
  ${EndIf}
!macroend
