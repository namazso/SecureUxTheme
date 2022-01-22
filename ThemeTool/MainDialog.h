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
#pragma once
#include "dlg.h"
#include "utl.h"

enum class PatcherState : size_t
{
  No,
  Yes,
  Probably,
  Outdated
};

class MainDialog
{
  HWND _hwnd;

  MAKE_IDC_MEMBER(_hwnd, BUTTON_APPLY);
  MAKE_IDC_MEMBER(_hwnd, BUTTON_PATCH);
  MAKE_IDC_MEMBER(_hwnd, BUTTON_HELP);
  MAKE_IDC_MEMBER(_hwnd, BUTTON_INSTALL);
  MAKE_IDC_MEMBER(_hwnd, BUTTON_UNINSTALL);
  MAKE_IDC_MEMBER(_hwnd, CHECK_COLORS);
  MAKE_IDC_MEMBER(_hwnd, CHECK_EXPLORER);
  MAKE_IDC_MEMBER(_hwnd, CHECK_IGNORE_BACKGROUND);
  MAKE_IDC_MEMBER(_hwnd, CHECK_IGNORE_COLOR);
  MAKE_IDC_MEMBER(_hwnd, CHECK_IGNORE_CURSOR);
  MAKE_IDC_MEMBER(_hwnd, CHECK_IGNORE_DESKTOP_ICONS);
  MAKE_IDC_MEMBER(_hwnd, CHECK_IGNORE_SOUND);
  MAKE_IDC_MEMBER(_hwnd, CHECK_IGNORE_SCREENSAVER);
  MAKE_IDC_MEMBER(_hwnd, CHECK_LOGONUI);
  MAKE_IDC_MEMBER(_hwnd, CHECK_SYSTEMSETTINGS);
  MAKE_IDC_MEMBER(_hwnd, LIST);
  MAKE_IDC_MEMBER(_hwnd, LOG);
  MAKE_IDC_MEMBER(_hwnd, STATIC_ASADMIN);
  MAKE_IDC_MEMBER(_hwnd, STATIC_EXPLORER);
  MAKE_IDC_MEMBER(_hwnd, STATIC_INSTALLED);
  MAKE_IDC_MEMBER(_hwnd, STATIC_LOADED);
  MAKE_IDC_MEMBER(_hwnd, STATIC_LOGONUI);
  MAKE_IDC_MEMBER(_hwnd, STATIC_NEEDS_PATCHING);
  MAKE_IDC_MEMBER(_hwnd, STATIC_STYLE);
  MAKE_IDC_MEMBER(_hwnd, STATIC_SYSTEMSETTINGS);
  MAKE_IDC_MEMBER(_hwnd, STATIC_NOTADMIN);

  PatcherState _is_installed;
  PatcherState _is_loaded;
  PatcherState _is_explorer;
  PatcherState _is_systemsettings;
  PatcherState _is_logonui;

  const bool _is_elevated = utl::is_elevated();
  const std::pair<std::wstring, std::wstring> _process_user = utl::process_user();
  const std::pair<std::wstring, std::wstring> _session_user = utl::session_user();

  std::list<std::wstring> _names;

  void Log(const wchar_t* fmt, ...);

  static bool IsInstalledForExecutable(const wchar_t* executable);
  static DWORD InstallForExecutable(const wchar_t* executable);
  static DWORD UninstallForExecutable(const wchar_t* executable);

  DWORD UninstallInternal();
  void Uninstall();
  void Install();
  void UpdatePatcherState();
  void UpdatePatcherStateDisplay();

  HRESULT PatchThemeInternal(int id);
  void SelectTheme(int id);
  void ApplyTheme(int id);
  void PatchTheme(int id);
  int CurrentSelection();

public:
  MainDialog(HWND hDlg, void*);

  INT_PTR DlgProc(UINT uMsg, WPARAM wParam, LPARAM lParam);
};