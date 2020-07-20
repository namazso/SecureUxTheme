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
  std::pair<const void*, size_t> get_resource(WORD type, WORD id);
  int atom_reference_count(const wchar_t* name);
  bool is_elevated();

  const std::pair<std::wstring, std::wstring>& session_user();
  const std::pair<std::wstring, std::wstring>& process_user();

  DWORD read_file(std::wstring_view path, std::vector<char>& content);
  DWORD write_file(std::wstring_view path, const void* data, size_t size);
  DWORD nuke_file(std::wstring_view path);

  DWORD get_KnownDllPath(std::wstring& wstr);

  std::pair<const void*, size_t> get_dll_blob();

  static void Fatal(HWND hwnd, const wchar_t* fmt, ...)
  {
    va_list args;
    va_start(args, fmt);
    wchar_t text[4096];
    vswprintf_s(text, fmt, args);
    va_end(args);
    MessageBoxW(hwnd, text, L"Fatal error", MB_OK | MB_ICONERROR);
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

    unique_redirection_disabler(unique_redirection_disabler&& other)
    {
      Wow64DisableWow64FsRedirection(&OldValue);
      std::swap(OldValue, other.OldValue);
    }

    ~unique_redirection_disabler()
    {
      Wow64RevertWow64FsRedirection(OldValue);
    }

    unique_redirection_disabler& operator=(const unique_redirection_disabler&) = delete;

    unique_redirection_disabler& operator=(unique_redirection_disabler&& other)
    {
      std::swap(OldValue, other.OldValue);
      return *this;
    }
  };
}