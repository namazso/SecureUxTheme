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

namespace utl {
  HINSTANCE get_instance();

  std::pair<const void*, size_t> get_resource(WORD type, WORD id);
  bool is_elevated();

  const std::pair<std::wstring, std::wstring> session_user();
  const std::pair<std::wstring, std::wstring> process_user();

  std::wstring ErrorToString(HRESULT error);

  inline int vfmt(std::wstring& str, const wchar_t* fmt, va_list args) {
    auto len = _vscwprintf(fmt, args);
    str.resize(len + 1);
    len = vswprintf_s(str.data(), str.size() + 1, fmt, args);
    if (len < 0)
      str.clear();
    return len;
  }

  inline int fmt(std::wstring& str, const wchar_t* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    const auto ret = vfmt(str, fmt, args);
    va_end(args);
    return ret;
  }

  inline int FormattedMessageBox(HWND hwnd, LPCWSTR caption, UINT type, LPCWSTR fmt, ...) {
    std::wstring str;
    va_list args;
    va_start(args, fmt);
    vfmt(str, fmt, args);
    va_end(args);
    return MessageBoxW(hwnd, str.data(), caption, type);
  }

  static void Fatal(HWND hwnd, const wchar_t* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    wchar_t text[4096];
    vswprintf_s(text, fmt, args);
    va_end(args);
    MessageBoxW(hwnd, text, L"Fatal error", MB_OK | MB_ICONERROR);
    PostQuitMessage(-1);
  }
} // namespace utl