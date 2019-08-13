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

Var LABEL
Var CHECKBOX_EXPLORER
Var CHECKBOX_SETTINGS

Function install_page
	nsDialogs::Create 1018
	Pop $0
	
	${NSD_CreateCheckbox} 2% 8u 46% 8u "Also hook explorer (unsafe)"
	Pop $CHECKBOX_EXPLORER
	
	${NSD_CreateCheckbox} 2% 18u 46% 8u "Also hook SystemSettings"
	Pop $CHECKBOX_SETTINGS
	
	${NSD_CreateButton} 2% 30u 22% 15u "Install"
	Pop $1
	GetFunctionAddress $0 OnInstall
	nsDialogs::OnClick $1 $0
	
	${NSD_CreateButton} 26% 30u 22% 15u "Uninstall"
	Pop $1
	GetFunctionAddress $0 OnUninstall
	nsDialogs::OnClick $1 $0
	
	${NSD_CreateGroupBox} 0 0 50% 48u ""
	Pop $1
	
	${NSD_CreateButton} 52% 4u 48% 20u "Fix signature of style"
	Pop $1
	GetFunctionAddress $0 OnFixSignature
	nsDialogs::OnClick $1 $0
	
	${NSD_CreateButton} 52% 28u 48% 20u "Hooked Personalization"
	Pop $1
	GetFunctionAddress $0 OnHookedPersonalization
	nsDialogs::OnClick $1 $0
	
	${NSD_CreateLabel} 0 52u 100% 100u "\
	- Hooking SystemSettings enables custom themes in Themes (Settings app)$\n\
	${U+00A0}${U+00A0}- However that is only available in Windows 10 1703+$\n\
	- Hooking explorer enables custom themes in Personalization (Control Panel)$\n\
	${U+00A0}${U+00A0}- It may or may not also break certain 32bit programs using explorer$\n\
	${U+00A0}${U+00A0}- Instead you can start a single hooked instance with $\"Hooked Personalization$\"$\n\
	- Styles still need to be signed, it just doesn't need to be valid$\n\
	${U+00A0}${U+00A0}- You can add an invalid signature to styles with $\"Fix signature of style$\"$\n"
	Pop $1
	
	${NSD_CreateLabel} 0 122u 100% 10u ""
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
	
	DeleteRegValue HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$0" "GlobalFlag"
	DeleteRegValue HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$0" "VerifierDlls"
FunctionEnd

Function OnFixSignature
	nsDialogs::SelectFileDialog open "" "Style|*.msstyles"
	Pop $0
	${If} $0 != ""
		File /oname=$TEMP\ThemeInvalidSigner.exe bin\Release\Win32\ThemeInvalidSigner.exe
		;ExecWait '"$TEMP\ThemeInvalidSigner.exe" "$0"' $0
		nsExec::ExecToStack '"$TEMP\ThemeInvalidSigner.exe" "$0"'
		Pop $0 # return value
		Pop $1 # stdout
		
		${If} $1 != ""
			${NSD_SetText} $LABEL $1
		${Else}
			${NSD_SetText} $LABEL "Program returned with error $0."
		${EndIf}
		
		;${If} $0 != 0
		;	${NSD_SetText} $LABEL "Program returned with error $0."
		;${Else}
		;	${NSD_SetText} $LABEL "Signature successfully fixed."
		;${EndIf}
	${EndIf}
FunctionEnd

Function OpenPersionalization
	ExecShellWait "" "$WINDIR\explorer.exe" "/separate,shell:::{ED834ED6-4B5A-4bfe-8F11-A626DCB6A921}"
FunctionEnd

Function OnHookedPersonalization
	${If} ${IsNativeAMD64}
		${DisableX64FSRedirection}
		SetRegView 64
	${EndIf}
	
	ReadRegDWORD $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe" "GlobalFlag"
	
	${If} $0 != 0x100
		Push "explorer.exe"
		Call IFEOAddEntry
		Call OpenPersionalization
		Push "explorer.exe"
		Call IFEODeleteEntry
	${Else}
		Call OpenPersionalization
	${EndIf}
FunctionEnd

Function InstallRegistryKeys
	; ensure hook doesn't get installed if we failed installing dll
	IfFileExists $SYSDIR\SecureUxTheme.dll found
		Return
	found:
	
	Push "winlogon.exe"
	Call IFEOAddEntry
	Push "dwm.exe"
	Call IFEOAddEntry
	
	${NSD_GetState} $CHECKBOX_EXPLORER $0
	${If} $0 == ${BST_CHECKED}
		Push "explorer.exe"
		Call IFEOAddEntry
	${EndIf}
	
	${NSD_GetState} $CHECKBOX_SETTINGS $0
	${If} $0 == ${BST_CHECKED}
		Push "SystemSettings.exe"
		Call IFEOAddEntry
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
	Call InstallRegistryKeys
	
	IfFileExists $SYSDIR\SecureUxTheme.dll found
		${NSD_SetText} $LABEL "Cannot install file!"
		Goto end
	found:
		${NSD_SetText} $LABEL "Successfully installed, please reboot!"
	end:
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
	Call IFEODeleteEntry
	Push "explorer.exe"
	Call IFEODeleteEntry
	Push "winlogon.exe"
	Call IFEODeleteEntry
	Push "dwm.exe"
	Call IFEODeleteEntry
	
	${NSD_SetText} $LABEL "Successfully uninstalled, please reboot!"
${Else}
	${NSD_SetText} $LABEL "Unsupported CPU architecture!"
${EndIf}
FunctionEnd

Section
SectionEnd
