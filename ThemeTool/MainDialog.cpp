// SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
// Copyright (C) 2020  namazso
// 
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#include "pch.h"

#include "MainDialog.h"

#include <chrono>

#include "main.h"
#include "signature.h"
#include "utl.h"

// using undocumented stuff is bad

extern "C" NTSYSAPI VOID NTAPI RtlGetNtVersionNumbers(
  _Out_opt_ PULONG NtMajorVersion,
  _Out_opt_ PULONG NtMinorVersion,
  _Out_opt_ PULONG NtBuildNumber
);

extern "C" NTSYSAPI NTSTATUS NTAPI RtlAdjustPrivilege(
  _In_ ULONG Privilege,
  _In_ BOOLEAN Enable,
  _In_ BOOLEAN Client,
  _Out_ PBOOLEAN WasEnabled
);

#define FLG_APPLICATION_VERIFIER (0x100)

static constexpr wchar_t kPatcherDllName[] = L"SecureUxTheme.dll";
static constexpr wchar_t kIFEO[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
static constexpr wchar_t kCurrentColorsPath[] = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\";
static constexpr wchar_t kCurrentColorsName[] = L"DefaultColors";
static constexpr wchar_t kCurrentColorsBackup[] = L"DefaultColors_backup";
static constexpr wchar_t kHelpText[] =
LR"(- For any custom themes to work SecureUxTheme or another patcher must be installed
- Styles need to be signed, the signature just doesn't need to be valid
  - To add an invalid signature to a style select a theme using it and click Patch
- After install and reboot, there are multiple ways to set themes:
  - If "Hook explorer" is enabled you can use "Personalization" to set a patched theme
  - If "Hook SystemSettings" is enabled you can use "Themes" to set a patched theme
)";
static constexpr wchar_t kHelpText2[] =
LR"(  - You can simply use ThemeTool to patch and apply themes (recommended)
- To prevent LogonUI from resetting colors either
  - DefaultColors must be renamed / deleted
  - or LogonUI must be hooked
)";

static DWORD RenameDefaultColors()
{
  const auto old_name = std::wstring{ ESTRt(kCurrentColorsPath) } + ESTRt(kCurrentColorsName);
  return utl::rename_key(old_name.c_str(), ESTRt(kCurrentColorsBackup));
}

static DWORD RestoreDefaultColors()
{
  const auto old_name = std::wstring{ ESTRt(kCurrentColorsPath) } + ESTRt(kCurrentColorsBackup);
  return utl::rename_key(old_name.c_str(), ESTRt(kCurrentColorsName));
}

static const wchar_t* PatcherStateText(PatcherState state)
{
  static const wchar_t* const text[] = { L"No", L"Yes", L"Probably", L"Outdated" };
  return text[(size_t)state];
}

static std::wstring GetPatcherDllPath()
{
  std::wstring path;
  const auto status = utl::get_KnownDllPath(path);
  if (status != NO_ERROR)
    utl::Fatal(nullptr, ESTRt(L"Cannot find KnownDllPath %08X"), status);

  path += ESTRt(L"\\");
  path += kPatcherDllName;
  return path;
}

static bool IsWin10()
{
  ULONG major = 0, minor = 0, build = 0;
  RtlGetNtVersionNumbers(&major, &minor, &build);
  return major == 10;
}

static bool IsLoadedInSession()
{
  const auto h = OpenEventW(
    SYNCHRONIZE,
    FALSE,
    ESTRt(L"SecureUxTheme_Loaded")
  );
  if (!h)
    return GetLastError() == ERROR_ACCESS_DENIED; // honestly, i have no idea how to set up permissions when creating it
  CloseHandle(h);
  return true;
}

static std::wstring GetWindowTextStr(HWND hwnd)
{
  SetLastError(0);
  const auto len = GetWindowTextLengthW(hwnd);
  const auto error = GetLastError();
  if (len == 0 && error != 0)
    return {};
  std::wstring str;
  str.resize(len + 1);
  str.resize(GetWindowTextW(hwnd, str.data(), str.size()));
  return str;
}

void MainDialog::Log(const wchar_t* fmt, ...)
{
  std::wstring str;
  va_list args;
  va_start(args, fmt);
  utl::vfmt(str, fmt, args);
  va_end(args);
  auto log = GetWindowTextStr(_hwnd_LOG);
  if(!log.empty())
    log.append(ESTRt(L"\r\n"));
  //LARGE_INTEGER li{};
  //QueryPerformanceCounter(&li);
  
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds >(
  std::chrono::system_clock::now().time_since_epoch()
    ).count();
  log.append(std::to_wstring(ms));
  log.append(ESTRt(L" > "));
  log.append(str);
  SetWindowTextW(_hwnd_LOG, log.c_str());
}

bool MainDialog::IsInstalledForExecutable(const wchar_t* executable)
{
  const auto subkey = std::wstring{ ESTRt(kIFEO) } +executable;
  DWORD GlobalFlag = 0;
  DWORD GlobalFlag_size = sizeof(GlobalFlag);
  const auto ret1 = RegGetValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    ESTRt(L"GlobalFlag"),
    RRF_RT_REG_DWORD | RRF_ZEROONFAILURE,
    nullptr,
    &GlobalFlag,
    &GlobalFlag_size
  );
  wchar_t VerifierDlls[257];
  DWORD VerifierDlls_size = sizeof(VerifierDlls);
  const auto ret2 = RegGetValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    ESTRt(L"VerifierDlls"),
    RRF_RT_REG_SZ | RRF_ZEROONFAILURE,
    nullptr,
    VerifierDlls,
    &VerifierDlls_size
  );
  return GlobalFlag & FLG_APPLICATION_VERIFIER && 0 == _wcsicmp(VerifierDlls, kPatcherDllName);
}

DWORD MainDialog::InstallForExecutable(const wchar_t* executable)
{
  const auto subkey = std::wstring{ ESTRt(kIFEO) } +executable;
  DWORD GlobalFlag = 0;
  DWORD GlobalFlag_size = sizeof(GlobalFlag);
  // we don't care if it fails
  RegGetValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    ESTRt(L"GlobalFlag"),
    RRF_RT_REG_DWORD | RRF_ZEROONFAILURE,
    nullptr,
    &GlobalFlag,
    &GlobalFlag_size
  );
  GlobalFlag |= FLG_APPLICATION_VERIFIER;
  auto ret = RegSetKeyValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    ESTRt(L"GlobalFlag"),
    REG_DWORD,
    &GlobalFlag,
    sizeof(GlobalFlag)
  );
  if(!ret)
  {
    ret = RegSetKeyValueW(
      HKEY_LOCAL_MACHINE,
      subkey.c_str(),
      ESTRt(L"VerifierDlls"),
      REG_SZ,
      kPatcherDllName,
      sizeof(kPatcherDllName)
    );
  }
  return ret;
}

DWORD MainDialog::UninstallForExecutable(const wchar_t* executable)
{
  const auto subkey = std::wstring{ ESTRt(kIFEO) } +executable;
  DWORD GlobalFlag = 0;
  DWORD GlobalFlag_size = sizeof(GlobalFlag);
  // we don't care if it fails
  RegGetValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    ESTRt(L"GlobalFlag"),
    RRF_RT_REG_DWORD | RRF_ZEROONFAILURE,
    nullptr,
    &GlobalFlag,
    &GlobalFlag_size
  );
  GlobalFlag &= ~FLG_APPLICATION_VERIFIER;
  DWORD ret = ERROR_SUCCESS;
  if(!GlobalFlag)
  {
    ret = RegDeleteKeyValueW(
      HKEY_LOCAL_MACHINE,
      subkey.c_str(),
      ESTRt(L"GlobalFlag")
    );
  }
  else
  {
    ret = RegSetKeyValueW(
      HKEY_LOCAL_MACHINE,
      subkey.c_str(),
      ESTRt(L"GlobalFlag"),
      REG_DWORD,
      &GlobalFlag,
      sizeof(GlobalFlag)
    );
  }

  // query it again, so we don't delete the other key if we failed removing the flag somehow, that would login loop
  GlobalFlag_size = sizeof(GlobalFlag);
  RegGetValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    ESTRt(L"GlobalFlag"),
    RRF_RT_REG_DWORD | RRF_ZEROONFAILURE,
    nullptr,
    &GlobalFlag,
    &GlobalFlag_size
  );
  if(!(GlobalFlag & FLG_APPLICATION_VERIFIER))
  {
    // FLG_APPLICATION_VERIFIER is not set, we don't care how we got here, nor if we succeed deleting VerifierDlls
    ret = ERROR_SUCCESS;

    RegDeleteKeyValueW(
      HKEY_LOCAL_MACHINE,
      subkey.c_str(),
      ESTRt(L"VerifierDlls")
    );
  }

  return ret;
}

DWORD MainDialog::UninstallInternal()
{
  Log(ESTRt(L"Uninstall started..."));

  const std::wstring remove_from[] = {
    std::wstring(ESTRt(L"winlogon.exe")),
    std::wstring(ESTRt(L"explorer.exe")),
    std::wstring(ESTRt(L"SystemSettings.exe")),
    std::wstring(ESTRt(L"dwm.exe")),
    std::wstring(ESTRt(L"LogonUI.exe"))
  };

  DWORD ret = ERROR_SUCCESS;
  auto failed = false;

  for (const auto executable : remove_from)
  {
    ret = UninstallForExecutable(executable.c_str());
    Log(ESTRt(L"UninstallForExecutable(\"%s\") returned %08X"), executable.c_str(), ret);
    failed = ret != 0;
    if (failed)
      break;
  }

  if (failed)
  {
    utl::FormattedMessageBox(
      _hwnd,
      ESTRt(L"Error"),
      MB_OK | MB_ICONERROR,
      ESTRt(L"Uninstalling failed, see log for more info. Error: %s"),
      utl::ErrorToString(ret).c_str()
    );
    return ret;
  }

  const auto dll_path = GetPatcherDllPath();
  ret = utl::nuke_file(dll_path);
  Log(ESTRt(L"utl::nuke_file returned: %08X"), ret);
  if (ret)
  {
    utl::FormattedMessageBox(
      _hwnd,
      ESTRt(L"Warning"),
      MB_OK | MB_ICONWARNING,
      ESTRt(L"Uninstalling succeeded, but the file couldn't be removed. This may cause problems on reinstall. Error: %s"),
      utl::ErrorToString(ret).c_str()
    );
  }

  // we don't really care if it succeeds
  const auto restore_ret = RestoreDefaultColors();
  Log(ESTRt(L"RestoreDefaultColors returned %08X"), restore_ret);

  return ret;
}

void MainDialog::Uninstall()
{
  {
    utl::unique_redirection_disabler disabler{};

    // TODO: warn user if current theme not signed

    UninstallInternal();
  }

  UpdatePatcherState();
}

void MainDialog::Install()
{
  utl::unique_redirection_disabler disabler{};

  auto ret = UninstallInternal();

  if(ret)
  {
    utl::FormattedMessageBox(
      _hwnd,
      ESTRt(L"Error"),
      MB_OK | MB_ICONERROR,
      ESTRt(L"Installation cannot continue because uninstalling failed")
    );
    return;
  }

  Log(ESTRt(L"Install started..."));

  const auto dll_path = GetPatcherDllPath();
  const auto blob = utl::get_dll_blob();
  ret = utl::write_file(dll_path, blob.first, blob.second);
  Log(ESTRt(L"utl::write_file returned %08X"), ret);
  if(ret)
  {
    utl::FormattedMessageBox(
      _hwnd,
      ESTRt(L"Error"),
      MB_OK | MB_ICONERROR,
      ESTRt(L"Installing patcher DLL failed. Error: %s"),
      utl::ErrorToString(ret)
    );
    return;
  }

  ret = InstallForExecutable(ESTRt(L"winlogon.exe"));
  Log(ESTRt(L"InstallForExecutable(\"winlogon.exe\") returned %08X"), ret);
  if(ret)
  {
    utl::FormattedMessageBox(
      _hwnd,
      ESTRt(L"Error"),
      MB_OK | MB_ICONERROR,
      ESTRt(L"Installing main hook failed. Error: %s"),
      utl::ErrorToString(ret).c_str()
    );
    UninstallInternal();
    return;
  }

  const std::pair<HWND MainDialog::*, std::wstring> checks[]
  {
    { &MainDialog::_hwnd_CHECK_EXPLORER,       std::wstring{ESTRt(L"explorer.exe")}       },
    { &MainDialog::_hwnd_CHECK_LOGONUI,        std::wstring{ESTRt(L"LogonUI.exe")}        },
    { &MainDialog::_hwnd_CHECK_SYSTEMSETTINGS, std::wstring{ESTRt(L"SystemSettings.exe")} },
  };

  for(const auto& check : checks)
  {
    if (BST_CHECKED != Button_GetCheck(this->*check.first))
      continue;

    const auto ret = InstallForExecutable(check.second.c_str());
    Log(ESTRt(L"InstallForExecutable(\"%s\") returned %08X"), check.second.c_str(), ret);
    if(ret)
    {
      utl::FormattedMessageBox(
        _hwnd,
        ESTRt(L"Warning"),
        MB_OK | MB_ICONWARNING,
        ESTRt(L"Installing for \"%s\" failed. Error: %s"),
        check.second.c_str(),
        utl::ErrorToString(ret).c_str()
      );
    }
  }

  if(BST_CHECKED == Button_GetCheck(_hwnd_CHECK_COLORS))
  {
    const auto ret = RenameDefaultColors();
    Log(ESTRt(L"RenameDefaultColors returned %08X"), ret);
    if(ret && ret != ERROR_PATH_NOT_FOUND)
    {
      utl::FormattedMessageBox(
        _hwnd,
        ESTRt(L"Warning"),
        MB_OK | MB_ICONWARNING,
        ESTRt(L"Renaming CurrentColors failed. If you have the LogonUI problem consider using LogonUI hook. Error: %s"),
        utl::ErrorToString(ret).c_str()
      );
    }
  }

  const auto reboot = IDYES == utl::FormattedMessageBox(
    _hwnd,
    ESTRt(L"Success"),
    MB_YESNO,
    ESTRt(L"Installing succeeded, patcher will be loaded next boot. Do you want to reboot now?")
  );

  if(reboot)
  {
    BOOLEAN old = FALSE;
    const auto status = RtlAdjustPrivilege(19, TRUE, FALSE, &old);
    Log(ESTRt(L"RtlAdjustPrivilege returned %08X"), status);
    if(!NT_SUCCESS(status))
    {
      utl::FormattedMessageBox(
        _hwnd,
        ESTRt(L"Error"),
        MB_OK | MB_ICONERROR,
        ESTRt(L"Adjusting shutdown privilege failed. Error: %s"),
        utl::ErrorToString(RtlNtStatusToDosError(status)).c_str()
      );
      return;
    }

    const auto succeeded = ExitWindowsEx(EWX_REBOOT, 0);
    if(!succeeded)
    {
      ret = GetLastError();
      Log(ESTRt(L"ExitWindowsEx failed with GetLastError() = %08X"), ret);
      utl::FormattedMessageBox(
        _hwnd,
        ESTRt(L"Error"),
        MB_OK | MB_ICONERROR,
        ESTRt(L"Rebooting failed. Error: %s"),
        utl::ErrorToString(ret).c_str()
      );
    }
  }
}

void MainDialog::UpdatePatcherState()
{
  utl::unique_redirection_disabler d{};
  const auto dll_path = GetPatcherDllPath();
  const auto dll_expected_content = utl::get_dll_blob();
  bool file_has_content;
  bool file_is_same;
  DWORD file_error;

  {
    std::vector<char> content;
    file_error = utl::read_file(dll_path, content);
    file_has_content = !content.empty();
    const auto begin = (char*)dll_expected_content.first;
    const auto end = begin + dll_expected_content.second;
    file_is_same = std::equal(content.begin(), content.end(), begin, end);
  }

  const auto reg_winlogon = IsInstalledForExecutable(ESTRt(L"winlogon.exe"));
  const auto reg_explorer = IsInstalledForExecutable(ESTRt(L"explorer.exe"));
  const auto reg_systemsettings = IsInstalledForExecutable(ESTRt(L"SystemSettings.exe"));
  const auto reg_logonui = IsInstalledForExecutable(ESTRt(L"LogonUI.exe"));
  const auto is_loaded = IsLoadedInSession();
  Log(
    ESTRt(L"UpdatePatcherState: file_has_content %d file_is_same %d file_error %d is_loaded %d"),
    file_has_content, file_is_same, file_error, (int)is_loaded
  );
  _is_installed =
    (file_has_content && reg_winlogon)
    ? (file_is_same ? PatcherState::Yes : PatcherState::Outdated)
    : PatcherState::No;
  _is_loaded =
    is_loaded
    ? PatcherState::Yes
    : (_is_installed == PatcherState::Outdated || (!IsWin10() && _is_installed == PatcherState::Yes) ? PatcherState::Probably : PatcherState::No);
  _is_logonui = reg_logonui ? PatcherState::Yes : PatcherState::No;
  _is_explorer = reg_explorer ? PatcherState::Yes : PatcherState::No;
  _is_systemsettings = reg_systemsettings ? PatcherState::Yes : PatcherState::No;

  UpdatePatcherStateDisplay();
}

void MainDialog::UpdatePatcherStateDisplay()
{
  static constexpr std::pair<PatcherState MainDialog::*, HWND MainDialog::*> statics[] 
  {
    { &MainDialog::_is_installed,       &MainDialog::_hwnd_STATIC_INSTALLED       },
    { &MainDialog::_is_loaded,          &MainDialog::_hwnd_STATIC_LOADED          },
    { &MainDialog::_is_logonui,         &MainDialog::_hwnd_STATIC_LOGONUI         },
    { &MainDialog::_is_explorer,        &MainDialog::_hwnd_STATIC_EXPLORER        },
    { &MainDialog::_is_systemsettings,  &MainDialog::_hwnd_STATIC_SYSTEMSETTINGS  },
  };
  for (const auto& x : statics)
    SetWindowTextW(this->*x.second, PatcherStateText(this->*x.first));
}

MainDialog::MainDialog(HWND hDlg, void*)
  : _hwnd(hDlg)
{

  Log(ESTRt(L"Version " CI_VERSION));

  ULONG major = 0, minor = 0, build = 0;
  RtlGetNtVersionNumbers(&major, &minor, &build);
  Log(ESTRt(L"Running on %d.%d.%d flavor %01X"), major, minor, build & 0xFFFF, build >> 28);
  
  Log(ESTRt(L"MainDialog: is_elevated %d"), _is_elevated);

  Log(ESTRt(L"Session user: %s Process user: %s"), _session_user.second.c_str(), _process_user.second.c_str());

  auto hicon = (HICON)LoadImageW(
    utl::get_instance(),
    MAKEINTRESOURCEW(IDI_ICON1),
    IMAGE_ICON,
    0,
    0,
    LR_DEFAULTCOLOR | LR_DEFAULTSIZE
  );
  SendMessageW(_hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hicon);
  SendMessageW(_hwnd, WM_SETICON, ICON_BIG, (LPARAM)hicon);

  Static_SetText(_hwnd_STATIC_ASADMIN, PatcherStateText(_is_elevated ? PatcherState::Yes : PatcherState::No));

  Button_SetCheck(_hwnd_CHECK_COLORS, BST_CHECKED);

  Button_Enable(_hwnd_BUTTON_PATCH, FALSE);
  Button_Enable(_hwnd_BUTTON_APPLY, FALSE);

  if (!_is_elevated)
  {
    ShowWindow(_hwnd_BUTTON_INSTALL, SW_HIDE);
    ShowWindow(_hwnd_BUTTON_UNINSTALL, SW_HIDE);
    ShowWindow(_hwnd_CHECK_COLORS, SW_HIDE);
    ShowWindow(_hwnd_CHECK_EXPLORER, SW_HIDE);
    ShowWindow(_hwnd_CHECK_LOGONUI, SW_HIDE);
    ShowWindow(_hwnd_CHECK_SYSTEMSETTINGS, SW_HIDE);
    ShowWindow(_hwnd_BUTTON_HELP, SW_HIDE);
  }
  else
  {
    ShowWindow(_hwnd_STATIC_NOTADMIN, SW_HIDE);
  }
  

  ListView_SetExtendedListViewStyle(_hwnd_LIST, LVS_EX_AUTOSIZECOLUMNS | LVS_EX_FULLROWSELECT);
  LVCOLUMN col{};
  ListView_InsertColumn(_hwnd_LIST, 0, &col);
  SendMessage(_hwnd_LIST, LVM_SETTEXTBKCOLOR, 0, (LPARAM)CLR_NONE);

  //auto style = GetWindowStyle(_hwnd_LIST);
  //style |= LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL | LVS_ALIGNLEFT | LVS_NOCOLUMNHEADER;
  //SetWindowLongW(_hwnd_LIST, GWL_STYLE, style);

  int iCount = 0;
  g_pThemeManager2->GetThemeCount(&iCount);

  //int iCurrent = 0;
  //g_pThemeManager2->GetCurrentTheme(&iCurrent);

  const auto add_item = [this](LPCTSTR name, LPARAM lparam)
  {
    LVITEM lvitem
    {
      LVIF_PARAM,
      INT_MAX,
      0,
      0,
      0,
      (LPTSTR)_T("")
    };
    lvitem.lParam = lparam;
    const auto item = ListView_InsertItem(_hwnd_LIST, &lvitem);
    ListView_SetItemText(_hwnd_LIST, item, 0, (LPTSTR)name);
  };

  for (auto i = 0; i < iCount; ++i)
  {
    ITheme* pTheme = nullptr;
    g_pThemeManager2->GetTheme(i, &pTheme);

    const auto name = pTheme->GetDisplayName();

    add_item(name.c_str(), i);

    pTheme->Release();
  }

  // LVS_EX_AUTOSIZECOLUMNS just doesn't fucking work no matter where I put it
  ListView_SetColumnWidth(_hwnd_LIST, 0, LVSCW_AUTOSIZE);

  UpdatePatcherState();
}

void MainDialog::SelectTheme(int id)
{
  if (id == -1)
  {
    Static_SetText(_hwnd_STATIC_STYLE, ESTRt(L"Error: Invalid selection"));
    return;
  }

  CComPtr<ITheme> pTheme = nullptr;
  auto result = g_pThemeManager2->GetTheme(id, &pTheme);
  if (FAILED(result))
  {
    Static_SetText(_hwnd_STATIC_STYLE, _T(""));
    Log(ESTRt(L"SelectTheme: g_pThemeManager2->GetTheme failed with %08X"), result);
    return;
  }

  std::wstring style;
  result = pTheme->GetVisualStyle(style);
  if (FAILED(result))
  {
    Static_SetText(_hwnd_STATIC_STYLE, _T(""));
    Log(ESTRt(L"SelectTheme: pTheme->GetVisualStyle failed with %08X"), result);
    return;
  }

  Static_SetText(_hwnd_STATIC_STYLE, style.c_str());

  Button_Enable(_hwnd_BUTTON_APPLY, TRUE);
  if(!style.empty() && sig::check_file(style.c_str()) == E_FAIL)
  {
    Static_SetText(_hwnd_STATIC_NEEDS_PATCHING, ESTRt(L"Style needs patching"));
    Button_SetText(_hwnd_BUTTON_APPLY, ESTRt(L"Patch and apply"));
    Button_Enable(_hwnd_BUTTON_PATCH, TRUE);
  }
  else
  {
    Static_SetText(_hwnd_STATIC_NEEDS_PATCHING, _T(""));
    Button_SetText(_hwnd_BUTTON_APPLY, ESTRt(L"Apply"));
    Button_Enable(_hwnd_BUTTON_PATCH, FALSE);
  }
}

HRESULT MainDialog::PatchThemeInternal(int id)
{
  Log(ESTRt(L"PatchThemeInternal(%d)"), id);

  bool patched = true;
  std::wstring style;

  {
    CComPtr<ITheme> pTheme = nullptr;
    auto result = g_pThemeManager2->GetTheme(id, &pTheme);
    if (SUCCEEDED(result))
    {
      result = pTheme->GetVisualStyle(style);
      if (SUCCEEDED(result))
      {
        if (!style.empty() && sig::check_file(style.c_str()) == E_FAIL)
          patched = false;
      }
      else
      {
        Log(ESTRt(L"pTheme->GetVisualStyle failed with %08X"), result);
      }
    }
    else
    {
      Log(ESTRt(L"g_pThemeManager2->GetTheme(%d) failed with %08X"), id, result);
      return result;
    }
  }

  HRESULT fix_result = NOERROR;
  if (!patched)
    fix_result = sig::fix_file(style.c_str());

  return fix_result;
}

void MainDialog::ApplyTheme(int id)
{
  Log(ESTRt(L"ApplyTheme(%d)"), id);

  if (id == -1)
    return; // invalid selection... whatever..

  if(_session_user != _process_user)
  {
    const auto answer = utl::FormattedMessageBox(
      _hwnd,
      ESTRt(L"Warning"),
      MB_YESNO | MB_ICONWARNING,
      ESTRt(LR"(This program is running as "%s", but you're logged in as "%s".
Setting a theme will apply it to user "%s".
Please note that setting a theme can be done as a non-administrator account.
Are you sure you want to continue?)"),
      _process_user.second.c_str(),
      _session_user.second.c_str(),
      _process_user.second.c_str()
    );

    if (answer == IDNO)
      return;
  }

  if(_is_installed != PatcherState::No)
  {
    const auto fix_result = PatchThemeInternal(id);

    if(!SUCCEEDED(fix_result))
    {
      Log(ESTRt(L"sig::fix_file failed: %08X"), fix_result);
      const auto answer = utl::FormattedMessageBox(
        _hwnd,
        ESTRt(L"Warning"),
        MB_YESNO | MB_ICONWARNING,
        ESTRt(LR"(You seem to be using SecureUxTheme, however the selected theme isn't patched, patching it now failed.
%s
The error encountered was: %s.
Do you want to continue?)"),
        !_is_elevated
          ? ESTRt(L"Try executing the tool as administrator.")
          : ESTRt(L"It seems like we're already elevated. Consider submitting a but report."),
        utl::ErrorToString(fix_result).c_str()
      );

      if (answer == IDNO)
        return;
    }

    if(_is_installed == PatcherState::Yes && _is_loaded == PatcherState::No)
    {
      const auto answer = utl::FormattedMessageBox(
        _hwnd,
        ESTRt(L"Warning"),
        MB_YESNO | MB_ICONWARNING,
        ESTRt(LR"(It seems like SecureUxTheme is installed but not loaded. Custom themes likely won't work.
Make sure you didn't forget to restart your computer after installing.
Do you still want to continue?)")
      );

      if (answer == IDNO)
        return;
    }
  }
  else
  {
    const auto answer = utl::FormattedMessageBox(
      _hwnd,
      ESTRt(L"Warning"),
      MB_YESNO | MB_ICONWARNING,
      ESTRt(LR"(You seem not to be using SecureUxTheme, and trying to apply a theme.
This won't work unless another patcher is installed or the theme is signed.
Are you sure you want to continue?)")
);

    if (answer == IDNO)
      return;
  }

  auto apply_flags = 0;
  
#define CHECK_FLAG(flag) apply_flags |= Button_GetCheck(_hwnd_CHECK_ ## flag) ? THEME_APPLY_FLAG_ ## flag : 0

  CHECK_FLAG(IGNORE_BACKGROUND);
  CHECK_FLAG(IGNORE_CURSOR);
  CHECK_FLAG(IGNORE_DESKTOP_ICONS);
  CHECK_FLAG(IGNORE_COLOR);
  CHECK_FLAG(IGNORE_SOUND);
  CHECK_FLAG(IGNORE_SCREENSAVER);

#undef CHECK_FLAG

  HRESULT result;

  {
    utl::unique_redirection_disabler disabler{};

    result = g_pThemeManager2->SetCurrentTheme(
      _hwnd,
      id,
      1,
      (THEME_APPLY_FLAGS)apply_flags,
      (THEMEPACK_FLAGS)0
    );
  }

  Log(ESTRt(L"ApplyTheme: SetCurrentTheme returned %08X"), result);

  if(FAILED(result))
  {
    utl::FormattedMessageBox(
      _hwnd,
      ESTRt(L"Error"),
      MB_OK | MB_ICONERROR,
      ESTRt(L"Theme setting failed. The following error was encountered:\r\n%s\r\nConsider submitting a bug report."),
      utl::ErrorToString(result).c_str()
    );
  }
}

void MainDialog::PatchTheme(int id)
{
  Log(ESTRt(L"PatchTheme(%d)"), id);

  if (id == -1)
    return; // invalid selection... whatever..

  const auto result = PatchThemeInternal(id);

  if (FAILED(result))
  {
    utl::FormattedMessageBox(
      _hwnd,
      ESTRt(L"Error"),
      MB_OK | MB_ICONERROR,
      ESTRt(L"Patching theme failed. The following error was encountered:\r\n%s\r\n%s"),
      utl::ErrorToString(result).c_str(),
      _is_elevated ? ESTRt(L"Consider sending a bug report") : ESTRt(L"Try running the program as Administrator")
    );
  }
}

int MainDialog::CurrentSelection()
{
  const auto count = ListView_GetSelectedCount(_hwnd_LIST);
  if (count != 1)
  {
    Log(ESTRt(L"CurrentSelection: count is %d, expected 1"), count);
    return -1;
  }

  LVITEM item{};
  item.iItem = ListView_GetSelectionMark(_hwnd_LIST);
  item.mask = LVIF_PARAM;
  ListView_GetItem(_hwnd_LIST, &item);
  return (int)item.lParam;
}

INT_PTR MainDialog::DlgProc(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
  UNREFERENCED_PARAMETER(lParam);
  switch (uMsg)
  {
  case WM_INITDIALOG:
    return FALSE; // do not select default control

  case WM_COMMAND:
    switch (LOWORD(wParam))
    {
    case IDOK:
    case IDCLOSE:
    case IDCANCEL:
      if (HIWORD(wParam) == BN_CLICKED)
        DestroyWindow(_hwnd);
      return TRUE;
    case IDC_BUTTON_HELP:
      if (HIWORD(wParam) == BN_CLICKED)
        MessageBoxW(
          _hwnd,
          (std::wstring{ ESTRt(kHelpText) } + ESTRt(kHelpText2)).c_str(),
          ESTRt(L"Help"),
          MB_OK
        );
      return TRUE;
    case IDC_BUTTON_INSTALL:
      if (HIWORD(wParam) == BN_CLICKED)
        Install();
      return TRUE;
    case IDC_BUTTON_UNINSTALL:
      if (HIWORD(wParam) == BN_CLICKED)
        Uninstall();
      return TRUE;
    case IDC_BUTTON_APPLY:
      if (HIWORD(wParam) == BN_CLICKED)
        ApplyTheme(CurrentSelection());
      return TRUE;
    case IDC_BUTTON_PATCH:
      if (HIWORD(wParam) == BN_CLICKED)
        PatchTheme(CurrentSelection());
      return TRUE;
    case IDC_CHECK_EXPLORER:
      if (HIWORD(wParam) == BN_CLICKED && Button_GetCheck(_hwnd_CHECK_EXPLORER) == BST_CHECKED)
        MessageBoxW(
          _hwnd,
          ESTRt(L"Are you sure about this? Hooking explorer on Win10 is rather pointless, and can cause instability, high"
          L" memory usage and bad performance in explorer. Consider (re-)reading the Help below the checkboxes."),
          ESTRt(L"Warning"),
          MB_OK | MB_ICONWARNING
        );
      return TRUE;
    }
    break;

  case WM_NOTIFY:
    {
    const auto nmhdr = (LPNMHDR)lParam;
    if (nmhdr->idFrom == IDC_LIST && nmhdr->code == NM_CLICK)
    {
      SelectTheme(CurrentSelection());
      return TRUE;
    }
    }
    return FALSE;

  case WM_CLOSE:
    DestroyWindow(_hwnd);
    return TRUE;

  case WM_DESTROY:
    PostQuitMessage(0);
    return TRUE;
  }
  return (INT_PTR)FALSE;
}
