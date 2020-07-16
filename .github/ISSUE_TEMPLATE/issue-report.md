---
name: Issue report
about: Login-loops, no or partial theme applying, etc..
title: ''
labels: ''
assignees: ''

---

**Screenshot of `winver`**
1. <kbd>Win</kbd> + <kbd>R</kbd>
2. Enter "winver"
3. Press OK
4. Take screenshot of the window and paste it in place of this list

**Screenshot of `regedit`**
1. <kbd>Win</kbd> + <kbd>R</kbd>
2. Enter "regedit"
3. Press OK
4. Paste `Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\winlogon.exe` into location bar and press enter
5. Take screenshot of the window and paste it in place of this list

**Does `winlogon` have `SecureUxTheme.dll` loaded?**
1. Download & install [Process Hacker](https://processhacker.sourceforge.io/)
2. Start it as administrator
3. Browse out `winlogon.exe`
4. Rightclick -> Properties -> Modules tab
5. Look for `SecureUxTheme.dll`. Ordering by "Company name" column can help.
6. State (or screenshot) whether it was present

**Is `SecureUxTheme.dll` present in `C:\Windows\system32`?**
\<yes / no>

**Theme url (if applicable)**
\<url>
