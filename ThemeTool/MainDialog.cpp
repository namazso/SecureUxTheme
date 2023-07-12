// SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
// Copyright (C) 2022  namazso <admin@namazso.eu>
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

static std::wstring GetWindowTextStr(HWND hwnd)
{
  SetLastError(0);
  const auto len = GetWindowTextLengthW(hwnd);
  const auto error = GetLastError();
  if (len == 0 && error != 0)
    return {};
  std::wstring str;
  str.resize(len + 1);
  str.resize(GetWindowTextW(hwnd, str.data(), (int)str.size()));
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

void MainDialog::Uninstall()
{
  Log(ESTRt(L"Uninstall started..."));

  const auto hr = secureuxtheme_uninstall();

  Log(ESTRt(L"secureuxtheme_uninstall() returned %08X"), hr);

  if (FAILED(hr))
    utl::FormattedMessageBox(
      _hwnd,
      ESTRt(L"Error"),
      MB_OK | MB_ICONERROR,
      ESTRt(L"Uninstall failed. Error: %s"),
      utl::ErrorToString(hr).c_str()
    );

  UpdatePatcherState();
}

void MainDialog::Install()
{
  Log(ESTRt(L"Install started..."));

  ULONG install_flags{};
  if (BST_CHECKED == Button_GetCheck(_hwnd_CHECK_EXPLORER))
    install_flags |= SECUREUXTHEME_INSTALL_HOOK_EXPLORER;
  if (BST_CHECKED == Button_GetCheck(_hwnd_CHECK_SYSTEMSETTINGS))
    install_flags |= SECUREUXTHEME_INSTALL_HOOK_SETTINGS;
  if (BST_CHECKED == Button_GetCheck(_hwnd_CHECK_LOGONUI))
    install_flags |= SECUREUXTHEME_INSTALL_HOOK_LOGONUI;
  if (BST_CHECKED == Button_GetCheck(_hwnd_CHECK_COLORS))
    install_flags |= SECUREUXTHEME_INSTALL_RENAME_DEFAULTCOLORS;

  const auto hr = secureuxtheme_install(install_flags);

  Log(ESTRt(L"secureuxtheme_install(%08X) returned %08X"), install_flags, hr);

  if (FAILED(hr))
  {
    utl::FormattedMessageBox(
      _hwnd,
      ESTRt(L"Error"),
      MB_OK | MB_ICONERROR,
      ESTRt(L"Install failed. Error: %s"),
      utl::ErrorToString(hr).c_str()
    );
  }
  else
  {
    const auto reboot = IDYES == utl::FormattedMessageBox(
      _hwnd,
      ESTRt(L"Success"),
      MB_YESNO,
      ESTRt(L"Installing succeeded, patcher will be loaded next boot. Do you want to reboot now?")
    );

    if (reboot)
    {
      BOOLEAN old = FALSE;
      const auto status = RtlAdjustPrivilege(19, TRUE, FALSE, &old);
      Log(ESTRt(L"RtlAdjustPrivilege returned %08X"), status);
      if (!NT_SUCCESS(status))
      {
        utl::FormattedMessageBox(
          _hwnd,
          ESTRt(L"Error"),
          MB_OK | MB_ICONERROR,
          ESTRt(L"Adjusting shutdown privilege failed. Error: %s"),
          utl::ErrorToString(HRESULT_FROM_WIN32(RtlNtStatusToDosError(status))).c_str()
        );
        return;
      }

      const auto succeeded = ExitWindowsEx(EWX_REBOOT, 0);
      if (!succeeded)
      {
        const auto ret = GetLastError();
        Log(ESTRt(L"ExitWindowsEx failed with GetLastError() = %08X"), ret);
        utl::FormattedMessageBox(
          _hwnd,
          ESTRt(L"Error"),
          MB_OK | MB_ICONERROR,
          ESTRt(L"Rebooting failed. Error: %s"),
          utl::ErrorToString(HRESULT_FROM_WIN32(ret)).c_str()
        );
      }
    }
  }
}

static const wchar_t* PatcherStateText(PatcherState state)
{
  static const wchar_t* const text[] = { L"No", L"Yes", L"Probably", L"Outdated" };
  return text[(size_t)state];
}

void MainDialog::UpdatePatcherState()
{
  const auto state = secureuxtheme_get_state_flags();
  _is_installed = state & SECUREUXTHEME_STATE_INSTALLED
    ? (state & SECUREUXTHEME_STATE_CURRENT
      ? PatcherState::Yes
      : PatcherState::Outdated)
    : PatcherState::No;
  _is_loaded = state & SECUREUXTHEME_STATE_LOADED ? PatcherState::Yes : PatcherState::No;
  _is_logonui = state & SECUREUXTHEME_STATE_LOGONUI_HOOKED ? PatcherState::Yes : PatcherState::No;
  _is_explorer = state & SECUREUXTHEME_STATE_EXPLORER_HOOKED ? PatcherState::Yes : PatcherState::No;
  _is_systemsettings = state & SECUREUXTHEME_STATE_SETTINGS_HOOKED ? PatcherState::Yes : PatcherState::No;

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

  ULONG theme_count{};
  themetool_get_theme_count(&theme_count);

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

  for (auto i = 0u; i < theme_count; ++i)
  {
    ITheme* theme{};
    themetool_get_theme(i, &theme);
    wchar_t name[256]{};
    themetool_theme_get_display_name(theme, name, std::size(name));
    add_item(name, i);
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

  ITheme* theme = nullptr;
  auto hr = themetool_get_theme(id, &theme);
  if (FAILED(hr))
  {
    Static_SetText(_hwnd_STATIC_STYLE, _T(""));
    Log(ESTRt(L"SelectTheme: themetool_get_theme(%d) failed with %08X"), id, hr);
    return;
  }

  wchar_t path[MAX_PATH];
  hr = themetool_theme_get_vs_path(theme, path, std::size(path));
  if (FAILED(hr))
  {
    Static_SetText(_hwnd_STATIC_STYLE, _T(""));
    Log(ESTRt(L"SelectTheme: themetool_theme_get_vs_path failed with %08X"), hr);
    if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND))
      utl::FormattedMessageBox(
        _hwnd,
        ESTRt(L"Warning"),
        MB_OK | MB_ICONWARNING,
        ESTRt(L"Getting visual style path failed!\n\nThis is often caused by incorrectly installed themes. Please make sure you copied all files and folders from the theme distribution before opening an issue.")
      );
    return;
  }

  Static_SetText(_hwnd_STATIC_STYLE, path);

  Button_Enable(_hwnd_BUTTON_APPLY, TRUE);
  if(path[0] && themetool_signature_check(path) == E_FAIL)
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

  wchar_t path[MAX_PATH]{};
  bool patched = true;

  {
    ITheme* theme = nullptr;
    auto result = themetool_get_theme(id, &theme);
    if (SUCCEEDED(result))
    {
      result = themetool_theme_get_vs_path(theme, path, std::size(path));
      if (SUCCEEDED(result))
      {
        if (path[0] && themetool_signature_check(path) == E_FAIL)
          patched = false;
      }
      else
      {
        Log(ESTRt(L"themetool_theme_get_vs_path failed with %08X"), result);
      }
    }
    else
    {
      Log(ESTRt(L"themetool_get_theme(%d) failed with %08X"), id, result);
      return result;
    }
  }

  HRESULT fix_result = S_OK;
  if (!patched && path[0])
    fix_result = themetool_signature_fix(path);

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

  ULONG apply_flags = 0;
  
#define CHECK_FLAG(flag) apply_flags |= Button_GetCheck(_hwnd_CHECK_ ## flag) ? THEMETOOL_APPLY_FLAG_ ## flag : 0

  CHECK_FLAG(IGNORE_BACKGROUND);
  CHECK_FLAG(IGNORE_CURSOR);
  CHECK_FLAG(IGNORE_DESKTOP_ICONS);
  CHECK_FLAG(IGNORE_COLOR);
  CHECK_FLAG(IGNORE_SOUND);
  CHECK_FLAG(IGNORE_SCREENSAVER);

#undef CHECK_FLAG

  HRESULT result;

  result = themetool_set_active(
    _hwnd,
    id,
    1,
    apply_flags,
    0
  );

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

  // reload theme details (patch status)
  SelectTheme(id);
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
    if (nmhdr->idFrom == IDC_LIST && nmhdr->code == LVN_ITEMCHANGED)
    {
      const auto pnmv = (LPNMLISTVIEW)lParam;
      if (pnmv->uNewState & LVIS_SELECTED)
      {
        SelectTheme(pnmv->iItem);
        return TRUE;
      }
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
