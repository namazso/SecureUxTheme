//  SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
//  Copyright (C) 2024  namazso <admin@namazso.eu>
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2.1 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

#include <themetool.h>

#include <atlcomcli.h>
#include <winternl.h>

#include <string>

typedef VOID(NTAPI LDR_ENUM_CALLBACK)(
  _In_ PLDR_DATA_TABLE_ENTRY ModuleInformation,
  _In_ PVOID Parameter,
  _Out_ BOOLEAN* Stop
);
typedef LDR_ENUM_CALLBACK* PLDR_ENUM_CALLBACK;

NTSTATUS NTAPI LdrEnumerateLoadedModules(
  _In_ BOOLEAN ReservedFlag,
  _In_ PLDR_ENUM_CALLBACK EnumProc,
  _In_opt_ PVOID Context
);

enum THEME_MANAGER_INITIALIZATION_FLAGS : unsigned {
  ThemeInitNoFlags = 0,
  ThemeInitCurrentThemeOnly = 1 << 0,
  ThemeInitFlagUnk1 = 1 << 1,
  ThemeInitFlagUnk2 = 1 << 2,
};

enum DESKTOP_WALLPAPER_POSITION {};

enum tagTHEMECAT {};

struct ISlideshowSettings;

// const CThemeFile::`vftable'{for `ITheme'}
struct ITheme : IUnknown {
private:
  virtual HRESULT WINAPI get_DisplayName(LPWSTR*) = 0;
  virtual HRESULT WINAPI put_DisplayName(LPWSTR) = 0;
  virtual HRESULT WINAPI get_VisualStyle(LPWSTR*) = 0;  // win8: get_ScreenSaver(LPWSTR*)
  virtual HRESULT WINAPI put_VisualStyle(LPWSTR) = 0;   // win8: set_ScreenSaver(LPWSTR)
  virtual HRESULT WINAPI get_VisualStyle2(LPWSTR*) = 0; // 1903: get_VisualStyleColor(LPWSTR*)
  virtual HRESULT WINAPI put_VisualStyle2(LPWSTR) = 0;  // 1903: put_VisualStyleColor(LPWSTR)

  // see "re" folder for full vtables

public:
  HRESULT GetDisplayName(std::wstring& name) {
    name.clear();
    LPWSTR lpwstr = nullptr;
    auto hr = get_DisplayName(&lpwstr);
    if (SUCCEEDED(hr) && lpwstr) {
      if (lpwstr) {
        name = lpwstr;
        SysFreeString(lpwstr);
      } else {
        hr = E_FAIL;
      }
    }
    return hr;
  }

  // we guess which one is the correct function, since it's vtable index shifted across windows versions
  HRESULT GetVisualStyle(std::wstring& path) {
    path.clear();
    LPWSTR lpwstr = nullptr;
    auto hr = get_VisualStyle2(&lpwstr);
    if (SUCCEEDED(hr) && lpwstr) {
      const auto lower = SysAllocString(lpwstr);
      for (auto it = lower; *it; ++it)
        *it = towlower(*it);
      const auto is_style = wcsstr(lower, L"msstyles") != nullptr;
      SysFreeString(lower);
      if (is_style) {
        path = lpwstr;
        SysFreeString(lpwstr);
        return hr;
      }
      SysFreeString(lpwstr);
    }
    lpwstr = nullptr;
    hr = get_VisualStyle(&lpwstr);
    if (SUCCEEDED(hr) && lpwstr) {
      const auto lower = SysAllocString(lpwstr);
      for (auto it = lower; *it; ++it)
        *it = towlower(*it);
      const auto is_style = wcsstr(lower, L"msstyles") != nullptr;
      SysFreeString(lower);
      if (is_style) {
        path = lpwstr;
        SysFreeString(lpwstr);
        return hr;
      }
      SysFreeString(lpwstr);
      return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }

    return hr;
  }
};

// const CThemeManager2::`vftable'
MIDL_INTERFACE("{c1e8c83e-845d-4d95-81db-e283fdffc000}")
IThemeManager2 : IUnknown {
  virtual HRESULT WINAPI Init(THEME_MANAGER_INITIALIZATION_FLAGS) = 0;
  virtual HRESULT WINAPI InitAsync(HWND, int) = 0;
  virtual HRESULT WINAPI Refresh() = 0;
  virtual HRESULT WINAPI RefreshAsync(HWND, int) = 0;
  virtual HRESULT WINAPI RefreshComplete() = 0;
  virtual HRESULT WINAPI GetThemeCount(int*) = 0;
  virtual HRESULT WINAPI GetTheme(int, ITheme**) = 0;
  virtual HRESULT WINAPI IsThemeDisabled(int, int*) = 0;
  virtual HRESULT WINAPI GetCurrentTheme(int*) = 0;
  virtual HRESULT WINAPI SetCurrentTheme(
    HWND parent,
    int theme_idx,
    int apply_now_not_only_registry, // 1 when called in Windows
    ULONG apply_flags,               // 0 when called in Windows
    ULONG pack_flags                 // 0 when called in Windows
  ) = 0;
  virtual HRESULT WINAPI GetCustomTheme(int*) = 0;
  virtual HRESULT WINAPI GetDefaultTheme(int*) = 0;
  virtual HRESULT WINAPI CreateThemePack(HWND, LPCWSTR, ULONG pack_flags) = 0;
  virtual HRESULT WINAPI CloneAndSetCurrentTheme(HWND, LPCWSTR, LPWSTR*) = 0;
  virtual HRESULT WINAPI InstallThemePack(HWND, LPCWSTR, int, ULONG pack_flags, LPWSTR*, ITheme**) = 0;
  virtual HRESULT WINAPI DeleteTheme(LPCWSTR) = 0;
  virtual HRESULT WINAPI OpenTheme(HWND, LPCWSTR, ULONG pack_flags) = 0;
  virtual HRESULT WINAPI AddAndSelectTheme(HWND, LPCWSTR, ULONG apply_flags, ULONG pack_flags) = 0;
  virtual HRESULT WINAPI SQMCurrentTheme() = 0;
  virtual HRESULT WINAPI ExportRoamingThemeToStream(IStream*, int) = 0;
  virtual HRESULT WINAPI ImportRoamingThemeFromStream(IStream*, int) = 0;
  virtual HRESULT WINAPI UpdateColorSettingsForLogonUI() = 0;
  virtual HRESULT WINAPI GetDefaultThemeId(GUID*) = 0;
  virtual HRESULT WINAPI UpdateCustomTheme() = 0;
};

static CComPtr<IThemeManager2> g_pThemeManager2;

static constexpr GUID CLSID_ThemeManager2 = {
  0x9324da94,
  0x50ec,
  0x4a14,
  {0xa7, 0x70, 0xe9, 0x0c, 0xa0, 0x3e, 0x7c, 0x8f}
};

HRESULT themetool_init() {
  if (g_pThemeManager2.p)
    return HRESULT_FROM_WIN32(ERROR_ALREADY_INITIALIZED);

  auto hr = CoInitialize(nullptr);
  if (FAILED(hr) && hr != CO_E_ALREADYINITIALIZED)
    return hr;

  hr = g_pThemeManager2.CoCreateInstance(CLSID_ThemeManager2);
  if (FAILED(hr))
    return hr;

  hr = g_pThemeManager2->Init(ThemeInitNoFlags);
  if (FAILED(hr))
    return hr;

  // win8
  LoadLibraryExW(L"advapi32", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
  // win10
  LoadLibraryExW(L"cryptsp", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);

  const auto ntdll = GetModuleHandleW(L"ntdll");
  if (!ntdll)
    return HRESULT_FROM_WIN32(GetLastError());

  const auto pLdrEnumerateLoadedModules = (decltype(&LdrEnumerateLoadedModules))GetProcAddress(ntdll, "LdrEnumerateLoadedModules");
  if (!pLdrEnumerateLoadedModules)
    return HRESULT_FROM_WIN32(GetLastError());

  bool was_patched = false;

  // This one only supports local process, so antiviruses dont spazz out over it. Or they just don't know it exists
  pLdrEnumerateLoadedModules(
    0,
    [](
      _In_ PLDR_DATA_TABLE_ENTRY ModuleInformation,
      _In_ PVOID Parameter,
      _Out_ BOOLEAN* Stop
    ) {
      *Stop = FALSE;

      constexpr BYTE bytes[] =
#if defined(_M_IX86)
      {
        0xB8,
        0x01,
        0x00,
        0x00,
        0x00, // mov eax, 1
        0xC2,
        0x18,
        0x00 // ret 18
      }
#elif defined(_M_X64)
      {
        0xB8,
        0x01,
        0x00,
        0x00,
        0x00, // mov eax, 1
        0xC3  // ret
      }
#elif defined(_M_ARM64)
        {
          0x20,
          0x00,
          0x80,
          0x52, // mov w0, #1
          0xC0,
          0x03,
          0x5F,
          0xD6 // ret
        }
#else
#error "Unsupported architecture"
#endif
      ;

      if (const auto pfn = GetProcAddress((HMODULE)ModuleInformation->DllBase, "CryptVerifySignatureW")) {
        DWORD old_protect = 0;
        const auto ret = VirtualProtect(
          (PVOID)pfn,
          sizeof(bytes),
          PAGE_EXECUTE_READWRITE,
          &old_protect
        );

        if (!ret)
          return;

        memcpy((PVOID)pfn, bytes, sizeof(bytes));

        *(bool*)Parameter = true;

        // we don't care if this fails, the page will just stay RWX at most
        VirtualProtect(
          (PVOID)pfn,
          sizeof(bytes),
          old_protect,
          &old_protect
        );
      }
    },
    &was_patched
  );

  if (!was_patched)
    return E_UNEXPECTED;

  return S_OK;
}

IThemeManager2* themetool_get_manager() {
  return g_pThemeManager2.p;
}

HRESULT themetool_get_theme_count(PULONG count) {
  *count = 0;
  int icount{};
  const auto hr = g_pThemeManager2->GetThemeCount(&icount);
  *count = icount;
  return hr;
}

HRESULT themetool_get_theme(ULONG idx, ITheme** theme) {
  return g_pThemeManager2->GetTheme((int)idx, theme);
}

HRESULT themetool_set_active(
  HWND parent,
  ULONG theme_idx,
  BOOLEAN apply_now_not_only_registry,
  ULONG apply_flags,
  ULONG pack_flags
) {
  const auto idx = (int)theme_idx;
  return g_pThemeManager2->SetCurrentTheme(parent, idx, !!apply_now_not_only_registry, apply_flags, pack_flags);
}

HRESULT themetool_theme_get_display_name(ITheme* theme, LPWSTR out, SIZE_T cch) {
  memset(out, 0, cch * sizeof(WCHAR));
  std::wstring str;
  const auto hr = theme->GetDisplayName(str);
  if (FAILED(hr))
    return hr;
  if (str.size() >= cch)
    return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
  std::copy_n(str.begin(), str.size(), out);
  return hr;
}

HRESULT themetool_theme_get_vs_path(ITheme* theme, LPWSTR out, SIZE_T cch) {
  memset(out, 0, cch * sizeof(WCHAR));
  std::wstring str;
  const auto hr = theme->GetVisualStyle(str);
  if (FAILED(hr))
    return hr;
  if (str.size() >= cch)
    return HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
  std::copy_n(str.begin(), str.size(), out);
  return hr;
}

void themetool_theme_release(ITheme* theme) {
  theme->Release();
}