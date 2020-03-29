# SecureUxTheme

## About

SecureUxTheme is a software that removes signature verification of styles from Windows.

## Features

* No system file modifications
* No driver needed
* Secure boot compatible
* Probably quite future-proof
* Fixes LogonUI resetting some colors on locking

## Limitations

Styles must still have a format-wise valid signature appended, it is just not verified. A tool for fixing styles without or with invalid one is included in the installer.

## Operating System Support\*

* Windows 8.1
* Windows 10 (tested: 1507, 1607, 1809, 1903, 1909, 20H1 Insider 18963)
* Future versions\*\*

\* Windows 7 or older will never be supported due to the way themes are implemented.

\*\* The current code doesn't depend on any code, binary or memory layout of uxtheme and related dlls, therefore should work unless major changes are made to how themes in general work.

## Download

[Latest release](https://github.com/namazso/SecureUxTheme/releases/latest/download/SecureUxTheme_setup.exe)

## Download is MALWARE???

Some silly antiviruses tend to flag the installer as malware, because it's elevated and unsigned (this method [clearly](https://www.securityweek.com/use-fake-code-signing-certificates-malware-surges) [works](https://www.zdnet.com/article/hackers-are-selling-legitimate-code-signing-certificates-to-evade-malware-detection/) [btw](http://signedmalware.org/)). I'm submitting all releases before release to Microsoft for analysis if they're detected, but I can't guarantee the same for all the other AVs. Since I'm not planning to have my IRL name plastered everywhere, I won't be getting a signing certificate either. However if you do have one and are willing help signing, please contact me.

## LogonUI fix

Locking Windows makes LogonUI reset certain colors and ignore the currently set style. This tool can fix this problem. A picture comparison showing the Task Manager opened after locking Windows without and with the fix can be seen here:

![LogonUI problem](resources/logonui_comparison.png)

Do note this feature might mess up some high contrast theme features when locking.

## Screenshot

Installer:

![Installer Screenshot](resources/screenshot_setup.png)

ThemeTool:

![ThemeTool Screenshot](resources/screenshot_themetool.png)

This is only a tool for enabling custom themes, no actual visual changes will be made.
Regardless, here's a cool theme for illustration:

![Screenshot](resources/screenshot.png)

[Theme used](https://7themes.su/load/windows_10_themes/temnye/10_pro_edition/34-1-0-1321)

## Where to get themes

I recommend [7themes.su](https://7themes.su/) for finding themes. Alternatives are [DeviantArt](https://www.deviantart.com/customization/skins/windows/win10/newest/?offset=0), and if you don't mind paying [cleodesktop](https://www.cleodesktop.com/), although I haven't tried that. Also, you can just search for themes with your favorite search engine.

## Donations

This software is provided completely free of charge to you, however I spent time and effort developing it. If you like this software, please consider making a donation:

* Bitcoin: 1N6UzYgzn3sLV33hB2iS3FvYLzD1G4CuS2
* Monero: 83sJ6GoeKf1U47vD9Tk6y2MEKJKxPJkECG3Ms7yzVGeiBYg2uYhBAUAZKNDH8VnAPGhwhZeqBnofDPgw9PiVtTgk95k53Rd

## Frequently Asked Questions

**Q: Help, SecureUxTheme broke my install and it's login looping now**

A: [Help: Login loop after installing SecureUxTheme](https://github.com/namazso/SecureUxTheme/wiki/Help:-Login-loop-after-installing-SecureUxTheme)

---

**Q: Help, a theme broke my install and it's login looping now**

A: [Help: Login loop after setting a theme](https://github.com/namazso/SecureUxTheme/wiki/Help:-Login-loop-after-setting-a-theme)

---

**Q: I just want a themed Windows, what do I do with all this?**

A: [Help: Step by step installing SecureUxTheme and a custom theme](https://github.com/namazso/SecureUxTheme/wiki/Help:-Step-by-step-installing-SecureUxTheme-and-a-custom-theme)

---

**Q: I have 1909 or later, and the Address bar / Search bar is weird when clicked**

A: [Issue #6](https://github.com/namazso/SecureUxTheme/issues/6)

---

**Q: The installer is throwing some error, what do I do?**

A: Always follow the installer - reboot after each Install / Uninstall, do reinstalls like `uninstall - reboot - install - reboot` instead of installing twice in a row.

## Building

### Requirements

* Visual Studio 2017 (newer ones not tested)
* [Nullsoft Scriptable Install System](https://nsis.sourceforge.io/)
* [NSIS HandleFileDragDrop plug-in](https://nsis.sourceforge.io/HandleFileDragDrop_plug-in)

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
