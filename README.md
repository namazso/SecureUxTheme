# SecureUxTheme

## About

SecureUxTheme is a software that removes signature verification of styles from Windows.

## Features

* No system file modifications
* No driver needed
* Secure boot compatible
* Probably quite future-proof

## Limitations

Styles must still have a format-wise valid signature appended, it is just not verified. A tool for fixing styles without or with invalid one is included in the installer.

## Operating System Support

* Windows 10 1903 (tested)
* Built with support for Windows 7 and later (not tested)

## Download

[Latest release](https://github.com/namazso/SecureUxTheme/releases/latest/download/SecureUxTheme_setup.exe)

## Screenshot

This is only a tool for enabling custom themes, no actual visual changes will be made.
Regardless, here's a cool theme for illustration:

![Screenshot](https://raw.githubusercontent.com/namazso/SecureUxTheme/master/screenshot.png)

[Theme used](https://7themes.su/load/windows_10_themes/temnye/10_pro_edition/34-1-0-1321)

## Recovery

Despite best effort things may always break so bad they prevent booting up windows.
This section describes how to disable the software on a non-booting install:

1. See [this guide](https://www.wintips.org/how-to-edit-and-modify-registry-offline/) on editing registry offline
2. Navigate to `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\`
3. Delete the following keys: `systemsettings.exe`, `winlogon.exe`, `dwm.exe`
4. Done, the software should be disabled now and you can reboot.
5. After reboot you can completely remove the software by deleting `%windir%\system32\SecureUxTheme.dll`

## Building

### Requirements

* Visual Studio 2017 (newer ones not tested)
* [Nullsoft Scriptable Install System](https://nsis.sourceforge.io/)

### Compiling

1. Open SecureUxTheme.sln and click __Build Solution__ on x64/Release and Win32/Release settings
2. Use NSIS to compile installer.nsi to get the installer

## License Statement

	SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
	Copyright (C) 2019  namazso
	
	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
	
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
