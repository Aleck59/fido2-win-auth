; NSIS installer for fido2-win-auth.
; Installs the credential provider DLL, the enrollment tools (window and
; console) and the bundled libfido2 runtime DLLs, then self-registers the
; provider.
;
; Build from the repo root:  make installer   (defines DIST=dist)
; or directly:               makensis -DDIST=dist installer/installer.nsi

!ifndef DIST
  !define DIST "dist"
!endif

; What people read.
!define APPNAME     "FIDO win auth"
!define COMPANY     "Aleck59"
!define DESCRIPTION "Вход в Windows по ключу FIDO2 для локальных учётных записей"

; Stable internal id: the install directory and the uninstall registry key keep
; the old name so an existing installation is upgraded rather than orphaned.
!define APPID       "fido2-win-auth"
!define CLSID       "{b167f262-672c-49f7-ba9c-b981e7d5bb6d}"

Name "${APPNAME}"
OutFile "${DIST}/fido2-win-auth-setup.exe"
Icon "..\src\gui\app.ico"
UninstallIcon "..\src\gui\app.ico"
InstallDir "$PROGRAMFILES64\${APPID}"
RequestExecutionLevel admin
Unicode true
SetCompressor /SOLID lzma

!include "MUI2.nsh"

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_TEXT "Установка завершена.$\r$\n$\r$\nДалее зарегистрируйте ключ: «${APPNAME}» в меню Пуск (или enroll.exe в консоли). ОБЯЗАТЕЛЬНО сохраните запасной способ входа."
!define MUI_FINISHPAGE_RUN "$INSTDIR\fido2gui.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Зарегистрировать ключ сейчас"
!define MUI_FINISHPAGE_RUN_NOTCHECKED
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "Russian"
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"

  ; Binaries.
  File "${DIST}/fido2provider.dll"
  File "${DIST}/enroll.exe"
  File "${DIST}/fido2gui.exe"

  ; Bundled libfido2 runtime (fido2, cbor, crypto, zlib1).
  File "${DIST}/fido2.dll"
  File "${DIST}/cbor.dll"
  File "${DIST}/crypto.dll"
  File "${DIST}/zlib1.dll"

  ; Register the COM class and credential provider (via DllRegisterServer).
  ExecWait '"$SYSDIR\regsvr32.exe" /s "$INSTDIR\fido2provider.dll"' $0
  ${If} $0 <> 0
    MessageBox MB_ICONSTOP "Не удалось зарегистрировать провайдер (regsvr32 код $0)."
  ${EndIf}

  ; Start menu entry for the window; the console tool stays discoverable in
  ; the install directory.
  RMDir /r "$SMPROGRAMS\${APPID}"
  CreateDirectory "$SMPROGRAMS\${APPNAME}"
  CreateShortCut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" \
      "$INSTDIR\fido2gui.exe" "" "$INSTDIR\fido2gui.exe" 0

  ; Uninstaller + Add/Remove Programs entry.
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPID}" \
      "DisplayName" "${APPNAME}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPID}" \
      "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPID}" \
      "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPID}" \
      "Publisher" "${COMPANY}"
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPID}" \
      "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPID}" \
      "NoRepair" 1
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPID}" \
      "DisplayIcon" "$INSTDIR\fido2gui.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPID}" \
      "DisplayVersion" "0.0.2.0"
SectionEnd

Section "Uninstall"
  ; Unregister the provider first so LogonUI stops loading it.
  ExecWait '"$SYSDIR\regsvr32.exe" /s /u "$INSTDIR\fido2provider.dll"'

  Delete "$INSTDIR\fido2provider.dll"
  Delete "$INSTDIR\enroll.exe"
  Delete "$INSTDIR\fido2gui.exe"
  Delete "$INSTDIR\fido2.dll"
  Delete "$INSTDIR\cbor.dll"
  Delete "$INSTDIR\crypto.dll"
  Delete "$INSTDIR\zlib1.dll"
  Delete "$INSTDIR\uninstall.exe"
  RMDir /r "$SMPROGRAMS\${APPNAME}"
  RMDir /r "$SMPROGRAMS\${APPID}"
  RMDir "$INSTDIR"

  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPID}"

  ; Note: enrolled vault records under HKLM\SOFTWARE\fido2-win-auth\vaults are
  ; left in place on uninstall so a reinstall keeps working. Remove them with
  ; `enroll --remove <account>` or manually if you want a clean wipe.
SectionEnd
