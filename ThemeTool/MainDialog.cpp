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

#include "main.h"
#include "signature.h"
#include "utl.h"

static const wchar_t* PatcherStateText(PatcherState state)
{
  static const wchar_t* const text[] = { L"No", L"Yes", L"Probably", L"Outdated" };
  return text[(size_t)state];
}

static constexpr wchar_t kPatcherDllName[] = L"SecureUxTheme.dll";
static constexpr wchar_t kIFEO[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";

static std::wstring GetPatcherDllPath()
{
  std::wstring path;
  const auto status = utl::get_KnownDllPath(path);
  if (status != NO_ERROR)
    utl::Fatal(nullptr, L"Cannot find KnownDllPath %08X", status);

  path += L"\\";
  path += kPatcherDllName;
  return path;
}

static int WinlogonBypassCount()
{
  return utl::atom_reference_count(L"SecureUxTheme_CalledInWinlogon");
}

std::wstring GetWindowTextStr(HWND hwnd)
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
  va_list args;
  va_start(args, fmt);
  wchar_t text[0x1000];
  vswprintf_s(text, fmt, args);
  va_end(args);
  auto log = GetWindowTextStr(_hwnd_LOG);
  log.append(L"\r\n");
  log.append(text);
  SetWindowTextW(_hwnd_LOG, log.c_str());
}

bool MainDialog::IsInstalledForExecutable(const wchar_t* executable)
{
  const auto subkey = std::wstring{ kIFEO } +executable;
  DWORD GlobalFlag = 0;
  DWORD GlobalFlag_size = sizeof(GlobalFlag);
  const auto ret1 = RegGetValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    L"GlobalFlag",
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
    L"VerifierDlls",
    RRF_RT_REG_SZ | RRF_ZEROONFAILURE,
    nullptr,
    VerifierDlls,
    &VerifierDlls_size
  );
  Log(L"%s: (%d) GlobalFlag=%08X (%d) VerifierDlls=%s", executable, ret1, GlobalFlag, ret2, VerifierDlls);
  return GlobalFlag & 0x100 && 0 == _wcsicmp(VerifierDlls, kPatcherDllName);
}

void MainDialog::UpdatePatcherState()
{
  utl::unique_redirection_disabler d{};
  std::wstring dll_path = GetPatcherDllPath();
  const auto dll_expected_content = utl::get_dll_blob();
  bool file_has_content;
  bool file_is_same;
  {
    std::vector<char> content;
    utl::read_file(dll_path, content);
    file_has_content = !content.empty();
    const auto begin = (char*)dll_expected_content.first;
    const auto end = begin + dll_expected_content.second;
    file_is_same = std::equal(content.begin(), content.end(), begin, end);
  }
  const auto reg_winlogon = IsInstalledForExecutable(L"winlogon.exe");
  const auto reg_explorer = IsInstalledForExecutable(L"explorer.exe");
  const auto reg_systemsettings = IsInstalledForExecutable(L"SystemSettings.exe");
  const auto reg_logonui = IsInstalledForExecutable(L"LogonUI.exe");
  const auto bypass_count = WinlogonBypassCount();
  Log(
    L"file_has_content %d file_is_same %d reg_winlogon %d reg_explorer %d reg_systemsettings %d reg_logonui %d",
    file_has_content, file_is_same, reg_winlogon, reg_explorer, reg_systemsettings, reg_logonui
  );
  _is_installed =
    (file_has_content && reg_winlogon)
    ? (file_is_same ? PatcherState::Yes : PatcherState::Outdated)
    : PatcherState::No;
  _is_loaded =
    bypass_count > 0
    ? PatcherState::Yes
    : (_is_installed == PatcherState::Outdated ? PatcherState::Probably : PatcherState::No);
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
  const auto elevated = utl::is_elevated();

  Static_SetText(_hwnd_STATIC_ASADMIN, PatcherStateText(elevated ? PatcherState::Yes : PatcherState::No));

  if(!elevated)
  {
    Button_Enable(_hwnd_BUTTON_INSTALL, FALSE);
    Button_Enable(_hwnd_BUTTON_UNINSTALL, FALSE);
  }

  ListView_SetExtendedListViewStyle(_hwnd_LIST, LVS_EX_AUTOSIZECOLUMNS);
  LVCOLUMN col{};
  ListView_InsertColumn(_hwnd_LIST, 0, &col);
  SendMessage(_hwnd_LIST, LVM_SETTEXTBKCOLOR, 0, (LPARAM)CLR_NONE);

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

/*void MainDialog::SelectTheme(int id)
{
  if (id == -1)
  {
    Static_SetText(_hwnd_STATIC_STYLE, _T("Error: Invalid selection"));
    return;
  }

  ITheme* pTheme = nullptr;
  g_pThemeManager2->GetTheme(id, &pTheme);

  const auto style = pTheme->GetVisualStyle();

  Static_SetText(_hwnd_STATIC_STYLE, style);

  if(wcslen(style) > 1 && sig::check_file(style) == E_FAIL)
  {
    Static_SetText(_hwnd_STATIC_NEEDS_PATCH, _T("Style needs patching"));
    Button_SetText(_hwnd_BUTTON_APPLY, _T("Patch and apply"));
  }
  else
  {
    Static_SetText(_hwnd_STATIC_NEEDS_PATCH, _T(""));
    Button_SetText(_hwnd_BUTTON_APPLY, _T("Apply"));
  }

  pTheme->Release();
}

void MainDialog::ApplyTheme(int id)
{
  if (id == -1)
    return;

  {
    ITheme* pTheme = nullptr;
    g_pThemeManager2->GetTheme(id, &pTheme);

    const auto style = pTheme->GetVisualStyle();

    Static_SetText(_hwnd_STATIC_STYLE, style);

    if (wcslen(style) > 1 && sig::check_file(style) == E_FAIL)
      sig::fix_file(style, !g_is_elevated);

    SysFreeString(style);

    pTheme->Release();
  }

  // update patchedness state
  SelectTheme(id);

  auto apply_flags = 0;
  
#define CHECK_FLAG(flag) apply_flags |= Button_GetCheck(_hwnd_CHECK_ ## flag) ? THEME_APPLY_FLAG_ ## flag : 0

  CHECK_FLAG(IGNORE_BACKGROUND);
  CHECK_FLAG(IGNORE_CURSOR);
  CHECK_FLAG(IGNORE_DESKTOP_ICONS);
  CHECK_FLAG(IGNORE_COLOR);
  CHECK_FLAG(IGNORE_SOUND);

#undef CHECK_FLAG

  g_pThemeManager2->SetCurrentTheme(
    _hwnd,
    id,
    1,
    (THEME_APPLY_FLAGS)apply_flags,
    (THEMEPACK_FLAGS)0
  );
}

int MainDialog::CurrentSelection()
{
  const auto selid = ComboBox_GetCurSel(_hwnd_COMBO_THEMES);
  const auto name = std::make_unique<TCHAR[]>((size_t)ComboBox_GetLBTextLen(_hwnd_COMBO_THEMES, selid) + 1);
  ComboBox_GetLBText(_hwnd_COMBO_THEMES, selid, name.get());
  return isdigit(*name.get()) ? wcstol(name.get(), nullptr, 10) : -1;
}*/

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
    /*case IDC_COMBO_THEMES:
      if (HIWORD(wParam) == CBN_SELENDOK)
        SelectTheme(CurrentSelection());
      return TRUE;
    case IDC_BUTTON_APPLY:
      if (HIWORD(wParam) == BN_CLICKED)
        ApplyTheme(CurrentSelection());
      return TRUE;*/
    }
    break;

  case WM_CLOSE:
    DestroyWindow(_hwnd);
    return TRUE;

  case WM_DESTROY:
    PostQuitMessage(0);
    return TRUE;
  }
  return (INT_PTR)FALSE;
}
