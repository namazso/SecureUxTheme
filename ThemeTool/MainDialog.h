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
#pragma once
#include "dlg.h"

class MainDialog
{
  HWND _hwnd;

  MAKE_IDC_MEMBER(_hwnd, COMBO_THEMES);
  MAKE_IDC_MEMBER(_hwnd, CHECK_IGNORE_BACKGROUND);
  MAKE_IDC_MEMBER(_hwnd, CHECK_IGNORE_CURSOR);
  MAKE_IDC_MEMBER(_hwnd, CHECK_IGNORE_DESKTOP_ICONS);
  MAKE_IDC_MEMBER(_hwnd, CHECK_IGNORE_COLOR);
  MAKE_IDC_MEMBER(_hwnd, CHECK_IGNORE_SOUND);
  MAKE_IDC_MEMBER(_hwnd, STATIC_STYLE);
  MAKE_IDC_MEMBER(_hwnd, STATIC_NEEDS_PATCH);
  MAKE_IDC_MEMBER(_hwnd, BUTTON_APPLY);

  std::list<std::wstring> _names;

  void SelectTheme(int id);
  void ApplyTheme(int id);
  int CurrentSelection();

public:
  MainDialog(HWND hDlg, void*);

  INT_PTR DlgProc(UINT uMsg, WPARAM wParam, LPARAM lParam);
};