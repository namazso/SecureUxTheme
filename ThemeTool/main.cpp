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
#include "utl.h"

#pragma comment(linker, \
  "\"/manifestdependency:type='Win32' "\
  "name='Microsoft.Windows.Common-Controls' "\
  "version='6.0.0.0' "\
  "processorArchitecture='*' "\
  "publicKeyToken='6595b64144ccf1df' "\
  "language='*'\"")

#pragma comment(lib, "ComCtl32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")

// we use the builtin one so all our crt methods aren't resolved from ntdll
#pragma comment(lib, "ntdll.lib")

extern void dll_loaded(PVOID base, PCWSTR name);

HINSTANCE g_instance;
CComPtr<IThemeManager2> g_pThemeManager2;

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

int show_license()
{
  wchar_t file_name[MAX_PATH];

  //  Gets the temp path env string (no guarantee it's a valid path).
  wchar_t temp_path[MAX_PATH];
  auto ret = GetTempPathW(
    MAX_PATH,
    temp_path
  );
  if (ret > MAX_PATH || ret == 0)
    return POST_ERROR(L"GetTempPathW failed: %08X", GetLastError());

  ret = GetTempFileNameW(
    temp_path,
    L"SecureUxTheme",
    0,
    file_name
  );
  if (ret == 0)
    return POST_ERROR(L"GetTempFileNameW failed: %08X", GetLastError());

  const auto license = utl::get_resource(256, IDR_LICENSE);
  if(!license.first)
    return POST_ERROR(L"utl::get_resource failed: %08X", GetLastError());

  wcscat_s(file_name, L".txt");

  ret = utl::write_file(file_name, license.first, license.second);
  if (ret)
    return POST_ERROR(L"utl::write_file failed: %08X", ret);

  ret = (DWORD)ShellExecuteW(
    nullptr,
    L"edit",
    file_name,
    nullptr,
    nullptr,
    SW_SHOWNORMAL
  );

  if(ret <= 32)
    return POST_ERROR(L"ShellExecuteW failed: %08X", ret);

  return 0;
}

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

  const auto license_read = IDYES == MessageBoxW(
    nullptr,
    L"Have you read and agree to the license?\r\n"
    L"Answering \"No\" will open the license text.",
    L"License",
    MB_YESNO
  );

  return license_read ? main_gui(nCmdShow) : show_license();
}