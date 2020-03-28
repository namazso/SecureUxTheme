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

#include "main.h"

#include "dlg.h"
#include "MainDialog.h"
#include "signature.h"

#pragma comment(linker, \
  "\"/manifestdependency:type='Win32' "\
  "name='Microsoft.Windows.Common-Controls' "\
  "version='6.0.0.0' "\
  "processorArchitecture='*' "\
  "publicKeyToken='6595b64144ccf1df' "\
  "language='*'\"")

#pragma comment(lib, "ComCtl32.lib")

// we use the builtin one so all our crt methods aren't resolved from ntdll
#pragma comment(lib, "ntdll.lib")

extern void dll_loaded(PVOID base, PCWSTR name);

HINSTANCE g_instance;
CComPtr<IThemeManager2> g_pThemeManager2;
bool g_is_elevated;

static bool is_elevated()
{
  auto   result   = FALSE;
  HANDLE token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
  {
    TOKEN_ELEVATION elevation;
    DWORD           size = sizeof(TOKEN_ELEVATION);
    if (GetTokenInformation(
      token,
      TokenElevation,
      &elevation,
      sizeof(elevation),
      &size
    ))
      result = elevation.TokenIsElevated;
  }
  if (token)
    CloseHandle(token);
  return result;
}

inline int FormattedMessageBox(HWND hwnd, LPCTSTR caption, UINT type, LPCTSTR fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  TCHAR text[4096];
  _vstprintf_s(text, fmt, args);
  va_end(args);
  return MessageBox(hwnd, text, caption, type);
}

static int main_gui(int nCmdShow)
{
  INITCOMMONCONTROLSEX iccex
  {
    sizeof(INITCOMMONCONTROLSEX),
    ICC_WIN95_CLASSES
  };

#define POST_ERROR(...) FormattedMessageBox(nullptr, _T("Error"), MB_OK | MB_ICONERROR, __VA_ARGS__)

  if (!InitCommonControlsEx(&iccex))
    return POST_ERROR(L"InitCommonControlsEx failed, LastError = %08X", GetLastError());

  auto hr = CoInitialize(nullptr);
  if (FAILED(hr))
    return POST_ERROR(L"CoInitialize failed, hr = %08X", hr);

  hr = g_pThemeManager2.CoCreateInstance(CLSID_ThemeManager2);
  if (FAILED(hr))
    return POST_ERROR(L"CoCreateInstance failed, hr = %08X", hr);

  hr = g_pThemeManager2->Init(ThemeInitNoFlags);
  if (FAILED(hr))
    return POST_ERROR(L"g_pThemeManager2->Init failed, hr = %08X", hr);

  const auto themeui = LoadLibraryW(L"themeui");
  if (!themeui)
    return POST_ERROR(L"LoadLibrary(themeui) failed, LastError = %08X", GetLastError());

  dll_loaded(themeui, L"themeui");

  const auto dialog = CreateDialogParam(
    g_instance,
    MAKEINTRESOURCE(IDD_MAIN),
    nullptr,
    &DlgProcClassBinder<MainDialog>,
    0
  );
  ShowWindow(dialog, nCmdShow);

  MSG msg;
  while (GetMessage(&msg, nullptr, 0, 0))
  {
    if (!IsDialogMessage(dialog, &msg))
    {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
  }

  return (int)msg.wParam;
}

static int main_silent(size_t file_count, wchar_t** files, bool verysilent)
{
  HRESULT hr = NOERROR;
  std::wstring msg;
  for(auto i = 0u; i < file_count; ++i)
  {
    const auto file = files[i];
    const auto error = sig::fix_file(file);
    if (hr == NOERROR && FAILED(error))
      hr = error;
    WCHAR buf[1024];
    FormatMessageW(
      FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr,
      error,
      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
      buf,
      _ARRAYSIZE(buf),
      nullptr
    );
    wchar_t msgbuf[2048];
    wsprintf(msgbuf, L"%s: %s", file_count == 1 ? L"Result" : file, buf);
    msg += msgbuf;
  }
  if(!verysilent)
    MessageBoxW(nullptr, msg.c_str(), L"Result", FAILED(hr) ? MB_ICONERROR : MB_OK);
  return hr;
}

struct LocalFreeDeleter
{
  void operator()(void* p) const { if(p) LocalFree(p); }
};

int APIENTRY wWinMain(
  _In_ HINSTANCE     hInstance,
  _In_opt_ HINSTANCE hPrevInstance,
  _In_ LPWSTR        lpCmdLine,
  _In_ int           nCmdShow
)
{
  UNREFERENCED_PARAMETER(hPrevInstance);
  UNREFERENCED_PARAMETER(lpCmdLine);

  g_instance = hInstance;

  g_is_elevated = is_elevated();

  {
    int argc;
    const std::unique_ptr<wchar_t*, LocalFreeDeleter> argvbuf{ CommandLineToArgvW(lpCmdLine, &argc) };
    const auto argv = argvbuf.get();
    if (argc >= 2 && 0 == _wcsicmp(argv[0], L"/s"))
      return main_silent((size_t)argc - 1, argv + 1, argv[0][1] == L'S');
  }

  return main_gui(nCmdShow);
}