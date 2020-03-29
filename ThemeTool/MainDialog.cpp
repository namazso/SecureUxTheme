// SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
// Copyright (C) 2019  namazso
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

MainDialog::MainDialog(HWND hDlg, void*)
  : _hwnd(hDlg)
{
  int iCount;
  g_pThemeManager2->GetThemeCount(&iCount);

  int iCurrent;
  g_pThemeManager2->GetCurrentTheme(&iCurrent);

  for (auto i = 0; i < iCount; ++i)
  {
    ITheme* pTheme = nullptr;
    g_pThemeManager2->GetTheme(i, &pTheme);

    const auto name = pTheme->GetDisplayName();

    const auto display = std::to_wstring(i) + L": " + name;
    const auto combo_idx = ComboBox_AddString(_hwnd_COMBO_THEMES, display.c_str());

    //SysFreeString(name);

    pTheme->Release();
  }
}

void MainDialog::SelectTheme(int id)
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

  SysFreeString(style);

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
    case IDC_COMBO_THEMES:
      if (HIWORD(wParam) == CBN_SELENDOK)
        SelectTheme(CurrentSelection());
      return TRUE;
    case IDC_BUTTON_APPLY:
      if (HIWORD(wParam) == BN_CLICKED)
        ApplyTheme(CurrentSelection());
      return TRUE;
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
