// SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
// Copyright (C) 2024  namazso <admin@namazso.eu>
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

// T should be a class handling a dialog, having implemented these:
// T(HWND hDlg, void* user_param)
//   hDlg: the HWND of the dialog, guaranteed to be valid for the lifetime of the object
//   user_param: parameter passed to the function creating the dialog
// INT_PTR DlgProc(UINT uMsg, WPARAM wParam, LPARAM lParam)
template <typename T>
INT_PTR CALLBACK DlgProcClassBinder(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
  T* p;
  if (uMsg == WM_INITDIALOG) {
    p = new T(hDlg, (void*)lParam);
    SetWindowLongPtr(hDlg, GWLP_USERDATA, (LONG_PTR)p);
  } else {
    p = (T*)GetWindowLongPtr(hDlg, GWLP_USERDATA);
  }
  // there are some unimportant messages sent before WM_INITDIALOG
  const INT_PTR ret = p ? p->DlgProc(uMsg, wParam, lParam) : (INT_PTR)FALSE;
  if (uMsg == WM_NCDESTROY) {
    delete p;
    // even if we were to somehow receive messages after WM_NCDESTROY make sure we dont call invalid ptr
    SetWindowLongPtr(hDlg, GWLP_USERDATA, 0);
  }
  return ret;
}

#define MAKE_IDC_MEMBER(hwnd, name) HWND _hwnd_##name = GetDlgItem(hwnd, IDC_##name)
