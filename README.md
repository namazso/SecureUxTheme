# SecureUxTheme

![Downloads](https://img.shields.io/github/downloads/namazso/SecureUxTheme/total) ![GitHub Version](https://img.shields.io/github/v/release/namazso/SecureUxTheme) ![Scoop Version](https://img.shields.io/scoop/v/secureuxtheme?bucket=extras)  ![WinGet Version](https://img.shields.io/winget/v/namazso.SecureUXTheme)

## About

SecureUxTheme is a program that removes signature verification of styles in Windows.

## Features

* No system file modifications
* No driver needed
* Secure boot compatible
* Probably quite future-proof
* Fixes LogonUI resetting some colors on locking

## Operating System Support

* Windows 8.1 x86/x64
* Windows Server 2012 R2 x86/x64
* Windows 10 x86/x64/ARM64
* Windows Server 2016/2019/2022 x86/x64
* Windows 11 (RTM -> 24H2) x86/x64/ARM64
* Windows Server 2025 x86/x64/ARM64
* Future versions (untested) x86/x64/ARM64

## Download

[Latest release](https://github.com/namazso/SecureUxTheme/releases/latest/)

Scoop:

```shell
scoop bucket add extras
scoop install secureuxtheme
```

WinGet:

```shell
winget install namazso.SecureUXTheme
```

## Screenshot

This is only a tool for enabling custom themes; no actual visual changes will be made.  Regardless, here is a cool theme for illustration:

![Screenshot](https://github.com/user-attachments/assets/2c0301f2-8392-426d-9b19-bb29500a0eea)

Theme used: [10 Pro by niivu](https://github.com/niivu/Windows-10-themes/tree/main/10%20Pro)

## Where to get themes

I recommend [DeviantArt](https://www.deviantart.com/tag/windows11themes) for finding themes. Make sure that the theme you're about to apply is compatible with your Windows version.

## Frequently Asked Questions

### **Q: Where is ThemeTool?**

A: ThemeTool was removed as SecureUxTheme is now configuration-free. If you wish to use a tool for changing themes, please check out [ThemeToolSharp](https://github.com/namazso/ThemeToolSharp/). However, using it is not required anymore, you can simply use Personalization or Themes.

### **Q: Help, SecureUxTheme broke my installation, and it's login looping now**

A: [Help: Login loop after installing SecureUxTheme](https://github.com/namazso/SecureUxTheme/wiki/Help:-Login-loop-after-installing-SecureUxTheme)

### **Q: Help, a theme broke my installation, and it's login looping now**

A: [Help: Login loop after setting a theme](https://github.com/namazso/SecureUxTheme/wiki/Help:-Login-loop-after-setting-a-theme)

### **Q: I have 1909 or later, and the Address bar / Search bar is weird when clicked**

A: Consider using OldNewExplorer which fixes this. Alternatively, see [Issue #6](https://github.com/namazso/SecureUxTheme/issues/6).

### **Q: Can you make themes per-program?**

A: Unfortunately, this is [close to impossible](https://github.com/namazso/SecureUxTheme/issues/9#issuecomment-611897882). However, for Office programs, there is a [plugin](https://github.com/matafokka/ExcelDarkThemeFix) for fixing this.

## Building

### Requirements

* Visual Studio Build Tools 17.11.4 or later for x86, x64, and ARM64
* Windows 11 WDK (26100 or later)
* Windows 11 SDK (must match the WDK version)
* CMake 3.31 or later
* WiX Toolset 6.0.0 or later

### Steps

1. Configure and build the project for x86 into `cmake-build-release-x86`
2. Configure and build the project for x64 into `cmake-build-release-x64`
3. Configure and build the project for ARM64 with `-DBUILD_AS_ARM64X=ARM64` into `cmake-build-release-arm64`
4. Configure and build the project for ARM64EC with `-DBUILD_AS_ARM64X=ARM64EC` into `cmake-build-release-arm64ec`
5. Build the x86 installer with `dotnet clean -c Release && dotnet build -c Release -a x86 -o bin\Release_x86`
6. Build the x64 installer with `dotnet clean -c Release && dotnet build -c Release -a x64 -o bin\Release_x64`
7. Build the ARM64 installer with `dotnet clean -c Release && dotnet build -c Release -a ARM64 -o bin\Release_ARM64`
