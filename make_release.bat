call %AUTHENTICODE_SIGN% cmake-build-release-x86\SecureUxTheme4.dll
call %AUTHENTICODE_SIGN% cmake-build-release-x86\ThemeUiProxy.dll

call %AUTHENTICODE_SIGN% cmake-build-release-x64\SecureUxTheme4.dll
call %AUTHENTICODE_SIGN% cmake-build-release-x64\ThemeUiProxy.dll

call %AUTHENTICODE_SIGN% cmake-build-release-arm64ec\SecureUxTheme4.dll
call %AUTHENTICODE_SIGN% cmake-build-release-arm64ec\ThemeUiProxy.dll

dotnet build -c Release -a x86 -o bin\Release_x86
dotnet clean -c Release
dotnet build -c Release -a x64 -o bin\Release_x64
dotnet clean -c Release
dotnet build -c Release -a ARM64 -o bin\Release_ARM64
dotnet clean -c Release

move /Y bin\Release_x86\SecureUxTheme.msi bin\SecureUxTheme_x86.msi
move /Y bin\Release_x64\SecureUxTheme.msi bin\SecureUxTheme_x64.msi
move /Y bin\Release_ARM64\SecureUxTheme.msi bin\SecureUxTheme_ARM64.msi
