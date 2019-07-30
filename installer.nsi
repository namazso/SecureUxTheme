; SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
; Copyright (C) 2019  namazso
; 
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
; 
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
; 
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <https://www.gnu.org/licenses/>.

!include nsDialogs.nsh
!include LogicLib.nsh
!include WinCore.nsh ; MAKELONG
!include x64.nsh

Name "SecureUxTheme"
OutFile "SecureUxTheme_setup.exe"
Caption "$(^Name)"

Unicode true
CRCCheck on
XPStyle on
RequestExecutionLevel admin
BrandingText "by namazso"

LicenseData "LICENSE"
SubCaption 0 ": License"

Page license
Page custom install_page
!pragma warning disable 8000 ; "Page instfiles not used, no sections will be executed!"

Var BUTTON
Var BUTTON2
Var BUTTON3
Var LABEL

Function install_page
	nsDialogs::Create 1018
	Pop $0

	${NSD_CreateButton} 0 0 48% 15u "Install"
	Pop $BUTTON
	GetFunctionAddress $0 OnInstall
	nsDialogs::OnClick $BUTTON $0
	
	${NSD_CreateButton} 52% 0 48% 15u "Uninstall"
	Pop $BUTTON2
	GetFunctionAddress $0 OnUninstall
	nsDialogs::OnClick $BUTTON2 $0
	
	${NSD_CreateButton} 0 20u 100% 15u "Fix signature of style"
	Pop $BUTTON3
	GetFunctionAddress $0 OnFixSignature
	nsDialogs::OnClick $BUTTON3 $0

	${NSD_CreateLabel} 0 40u 75% 40u ""
	Pop $LABEL

	nsDialogs::Show
FunctionEnd

Function IFEOAddEntry
	Pop $0
	
	WriteRegDWORD HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$0" "GlobalFlag" 0x00000100
	WriteRegStr HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$0" "VerifierDlls" "SecureUxTheme.dll"
FunctionEnd

Function IFEODeleteEntry
	Pop $0
	
	DeleteRegKey HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$0"
FunctionEnd

Function OnFixSignature
	nsDialogs::SelectFileDialog open "" "Style|*.msstyles"
	Pop $0
	${If} $0 != ""
		File /oname=$TEMP\ThemeInvalidSigner.exe bin\Release\Win32\ThemeInvalidSigner.exe
		ExecWait '"$TEMP\ThemeInvalidSigner.exe" "$0"' $0
		
		${If} $0 != 0
			${NSD_SetText} $LABEL "Program returned with error $0."
		${Else}
			${NSD_SetText} $LABEL "Signature successfully fixed."
		${EndIf}
	${EndIf}
FunctionEnd

Function OnInstall
${If} ${IsNativeAMD64}
	${DisableX64FSRedirection}
	SetRegView 64
	File /oname=$SYSDIR\SecureUxTheme.dll bin\Release\x64\SecureUxTheme.dll
	Goto RegistryInstall
${ElseIf} ${IsNativeIA32}
	File /oname=$SYSDIR\SecureUxTheme.dll bin\Release\Win32\SecureUxTheme.dll
	
RegistryInstall:
	Push "systemsettings.exe"
	Push "winlogon.exe"
	Push "dwm.exe"
	Call IFEOAddEntry
	Call IFEOAddEntry
	Call IFEOAddEntry
	
	${NSD_SetText} $LABEL "Successfully installed, please reboot!"
${Else}
	${NSD_SetText} $LABEL "Unsupported CPU architecture!"
${EndIf}
FunctionEnd

Function OnUninstall
${If} ${IsNativeAMD64}
	${DisableX64FSRedirection}
	SetRegView 64
	Goto Uninstall
${ElseIf} ${IsNativeIA32}
	
Uninstall:
	Delete /REBOOTOK $SYSDIR\SecureUxTheme.dll
	Push "systemsettings.exe"
	Push "winlogon.exe"
	Push "dwm.exe"
	Call IFEODeleteEntry
	Call IFEODeleteEntry
	Call IFEODeleteEntry
	
	${NSD_SetText} $LABEL "Successfully uninstalled, please reboot!"
${Else}
	${NSD_SetText} $LABEL "Unsupported CPU architecture!"
${EndIf}
FunctionEnd

Section
SectionEnd
