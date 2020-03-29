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

#include "../ThemeTool/signature.cpp"

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
  DWORD error;
  WCHAR buf[1024];

  if (argc < 2)
  {
    wprintf(L"Usage: ThemeInvalidSigner <filename>\n");
    error = ERROR_INVALID_PARAMETER;
  }
  else
  {
    error = sig::fix_file(argv[1], false);
  }

  FormatMessageW(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    nullptr,
    error,
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    buf,
    _ARRAYSIZE(buf),
    nullptr
  );

  wprintf(L"Result: %s", buf);
  return error;
}
