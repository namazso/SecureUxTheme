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

#include "pch.h"

#include "dlg.h"
#include "MainDialog.h"
#include "utl.h"

#pragma comment(linker,                                     \
                "\"/manifestdependency:type='Win32' "       \
                "name='Microsoft.Windows.Common-Controls' " \
                "version='6.0.0.0' "                        \
                "processorArchitecture='*' "                \
                "publicKeyToken='6595b64144ccf1df' "        \
                "language='*'\"")

#pragma comment(lib, "ComCtl32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")

// we use the builtin one so all our crt methods aren't resolved from ntdll
#pragma comment(lib, "ntdll.lib")

std::pair<LPCVOID, SIZE_T> get_resource(HMODULE mod, WORD type, WORD id) {
  const auto rc = FindResource(
    mod,
    MAKEINTRESOURCE(id),
    MAKEINTRESOURCE(type)
  );
  if (!rc)
    return {nullptr, 0};
  const auto rc_data = LoadResource(mod, rc);
  const auto size = SizeofResource(mod, rc);
  if (!rc_data)
    return {nullptr, 0};
  const auto data = static_cast<const void*>(LockResource(rc_data));
  return {data, size};
}

static USHORT GetNativeArchitecture() {
  switch (USER_SHARED_DATA->NativeProcessorArchitecture) {
  case PROCESSOR_ARCHITECTURE_AMD64:
    return (USHORT)IMAGE_FILE_MACHINE_AMD64;
  case PROCESSOR_ARCHITECTURE_ARM:
    return (USHORT)IMAGE_FILE_MACHINE_ARM;
  case PROCESSOR_ARCHITECTURE_ARM64:
    return (USHORT)IMAGE_FILE_MACHINE_ARM64;
  case PROCESSOR_ARCHITECTURE_IA64:
    return (USHORT)IMAGE_FILE_MACHINE_IA64;
  case PROCESSOR_ARCHITECTURE_INTEL:
    return (USHORT)IMAGE_FILE_MACHINE_I386;
  default:
    break;
  }
  return 0;
}

int APIENTRY wWinMain(
  _In_ HINSTANCE instance,
  _In_opt_ HINSTANCE prev_instance,
  _In_ LPWSTR cmd_line,
  _In_ int cmd_show
) {
  UNREFERENCED_PARAMETER(prev_instance);
  UNREFERENCED_PARAMETER(cmd_line);

  const auto nth = RtlImageNtHeader(&__ImageBase);
  if (nth->FileHeader.Machine != GetNativeArchitecture()) {
    MessageBoxW(
      nullptr,
      L"Wrong architecture!",
      L"Error",
      MB_OK | MB_ICONERROR
    );
    return EXIT_FAILURE;
  }

  MessageBoxW(
    nullptr,
    L"This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.",
    L"Warranty disclaimer",
    MB_OK | MB_ICONWARNING
  );

  INITCOMMONCONTROLSEX iccex{
    sizeof(INITCOMMONCONTROLSEX),
    ICC_WIN95_CLASSES
  };

#define POST_ERROR(...) utl::FormattedMessageBox(nullptr, L"Error", MB_OK | MB_ICONERROR, __VA_ARGS__)

  if (!InitCommonControlsEx(&iccex))
    return POST_ERROR(L"InitCommonControlsEx failed, LastError = %08X", GetLastError());

  const auto hr = themetool_init();
  if ((uint32_t)hr == (uint32_t)0x80040154)
    return POST_ERROR(L"themetool_init failed, hr = %08X.\n\nThis is usually caused by corrupted files. Make sure you don't have any other theme patcher installed, and check for corrupted files with sfc /scannow", hr);
  if (FAILED(hr))
    return POST_ERROR(L"themetool_init failed, hr = %08X.\n\n%s", hr, utl::ErrorToString(hr).c_str());

  const auto dialog = CreateDialogParam(
    instance,
    MAKEINTRESOURCE(IDD_MAIN),
    nullptr,
    &DlgProcClassBinder<MainDialog>,
    0
  );

  RECT rc;
  GetWindowRect(dialog, &rc);

  const auto hwnd_monitor = MonitorFromWindow(dialog, MONITOR_DEFAULTTONEAREST);
  MONITORINFO monitor_info{};
  monitor_info.cbSize = sizeof(monitor_info);
  GetMonitorInfoW(hwnd_monitor, &monitor_info);

  const auto& monitor_rc = monitor_info.rcMonitor;

  const auto dialog_width = rc.right - rc.left;
  const auto dialog_height = rc.bottom - rc.top;

  const auto x = monitor_rc.left + (monitor_rc.right - monitor_rc.left - dialog_width) / 2;
  const auto y = monitor_rc.top + (monitor_rc.bottom - monitor_rc.top - dialog_height) / 2;

  SetWindowPos(dialog, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER); // Set window position to be both vertically and horizontally centered on the screen.
  ShowWindow(dialog, cmd_show);


  MSG msg{};
  while (GetMessage(&msg, nullptr, 0, 0)) {
    if (!IsDialogMessage(dialog, &msg)) {
      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }
  }

  return (int)msg.wParam;
}
