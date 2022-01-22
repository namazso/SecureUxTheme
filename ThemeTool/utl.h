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

namespace utl
{
  HINSTANCE get_instance();

  std::pair<const void*, size_t> get_resource(WORD type, WORD id);
  bool is_elevated();

  const std::pair<std::wstring, std::wstring> session_user();
  const std::pair<std::wstring, std::wstring> process_user();

  DWORD read_file(std::wstring_view path, std::vector<char>& content);
  DWORD write_file(std::wstring_view path, const void* data, size_t size);
  DWORD nuke_file(std::wstring_view path);

  DWORD open_key(PHKEY handle, const wchar_t* path, ULONG desired_access);
  DWORD rename_key(const wchar_t* old_path, const wchar_t* new_path);

  DWORD get_KnownDllPath(std::wstring& wstr);

  std::pair<const void*, size_t> get_dll_blob();

  std::wstring ErrorToString(HRESULT error);

  inline int vfmt(std::wstring& str, const wchar_t* fmt, va_list args)
  {
    auto len = _vscwprintf(fmt, args);
    str.resize(len + 1);
    len = vswprintf_s(str.data(), str.size() + 1, fmt, args);
    if(len < 0)
      str.clear();
    return len;
  }

  inline int fmt(std::wstring& str, const wchar_t* fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    const auto ret = vfmt(str, fmt, args);
    va_end(args);
    return ret;
  }

  inline int FormattedMessageBox(HWND hwnd, LPCTSTR caption, UINT type, LPCTSTR fmt, ...)
  {
    std::wstring str;
    va_list args;
    va_start(args, fmt);
    vfmt(str, fmt, args);
    va_end(args);
    return MessageBox(hwnd, str.data(), caption, type);
  }


  static void Fatal(HWND hwnd, const wchar_t* fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    wchar_t text[4096];
    vswprintf_s(text, fmt, args);
    va_end(args);
    MessageBoxW(hwnd, text, ESTRt(L"Fatal error"), MB_OK | MB_ICONERROR);
    PostQuitMessage(-1);
  }


  class unique_redirection_disabler
  {
    PVOID OldValue;
  public:
    unique_redirection_disabler()
    {
      Wow64DisableWow64FsRedirection(&OldValue);
    }

    unique_redirection_disabler(const unique_redirection_disabler&) = delete;

    unique_redirection_disabler(unique_redirection_disabler&& other) noexcept
    {
      Wow64DisableWow64FsRedirection(&OldValue);
      std::swap(OldValue, other.OldValue);
    }

    ~unique_redirection_disabler()
    {
      Wow64RevertWow64FsRedirection(OldValue);
    }

    unique_redirection_disabler& operator=(const unique_redirection_disabler&) = delete;

    unique_redirection_disabler& operator=(unique_redirection_disabler&& other) noexcept
    {
      std::swap(OldValue, other.OldValue);
      return *this;
    }
  };
}