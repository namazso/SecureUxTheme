1. Boot into command prompt. Various ways of doing so can be found [here](https://www.tenforums.com/tutorials/2294-boot-advanced-startup-options-windows-10-a.html)
2. Enter `regedit` then press return
3. Click `HKEY_LOCAL_MACHINE`
4. Click <kbd>File</kbd> > <kbd>Load Hive...</kbd>
5. Open `%windir%/system32/config/SOFTWARE`
   - Do note that you need this from your normal windows installation, and not WinPE (so the one on C: and not X: for most people)
4. When it asks a name type in anything
5. Open that key, and navigate to `Microsoft\Windows NT\CurrentVersion\Image File Execution Options\` in it
6. Delete values `VerifierDlls` and `GlobalFlag` from keys `systemsettings.exe`, `explorer.exe`, `winlogon.exe`, `LogonUI.exe`
   - You can just delete the keys for the ones that don't contain other values
   - Keys `systemsettings.exe`, `explorer.exe`, `LogonUI.exe` may not exist or not have the keys if you didn't install hook for them
7. Reboot. Your system should boot properly now
8. You can completely remove the software by deleting `%windir%\system32\SecureUxTheme.dll`, or just clicking Uninstall in the installer

For simplicity I also made a gif on performing steps 2 to 7 (inclusive):

![Recovery](recovery.gif)