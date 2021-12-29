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

enum THEME_MANAGER_INITIALIZATION_FLAGS : unsigned
{
  ThemeInitNoFlags            = 0,
  ThemeInitCurrentThemeOnly   = 1 << 0,
  ThemeInitFlagUnk1           = 1 << 1,
  ThemeInitFlagUnk2           = 1 << 2,
};

enum THEME_APPLY_FLAGS
{
  THEME_APPLY_FLAG_IGNORE_BACKGROUND    = 1 << 0,
  THEME_APPLY_FLAG_IGNORE_CURSOR        = 1 << 1,
  THEME_APPLY_FLAG_IGNORE_DESKTOP_ICONS = 1 << 2,
  THEME_APPLY_FLAG_IGNORE_COLOR         = 1 << 3,
  THEME_APPLY_FLAG_IGNORE_SOUND         = 1 << 4,
  THEME_APPLY_FLAG_IGNORE_SCREENSAVER   = 1 << 5,
  THEME_APPLY_FLAG_UNKNOWN              = 1 << 6, // something about window metrics
  THEME_APPLY_FLAG_UNKNOWN2             = 1 << 7,
  THEME_APPLY_FLAG_NO_HOURGLASS         = 1 << 8
};

enum THEMEPACK_FLAGS
{
  THEMEPACK_FLAG_UNKNOWN1     = 1 << 0, // setting this seems to supress hourglass
  THEMEPACK_FLAG_UNKNOWN2     = 1 << 1, // setting this seems to supress hourglass
  THEMEPACK_FLAG_SILENT       = 1 << 2, // hides all dialogs and prevents sound
  THEMEPACK_FLAG_ROAMED       = 1 << 3, // something about roaming
};

enum DESKTOP_WALLPAPER_POSITION {};
enum tagTHEMECAT {};

struct ISlideshowSettings;

// const CThemeFile::`vftable'{for `ITheme'}
class ITheme : public IUnknown
{
  virtual HRESULT WINAPI get_DisplayName(LPWSTR*) = 0;
  virtual HRESULT WINAPI put_DisplayName(LPWSTR) = 0;
  virtual HRESULT WINAPI get_VisualStyle(LPWSTR*) = 0;  // win8: get_ScreenSaver(LPWSTR*)
  virtual HRESULT WINAPI put_VisualStyle(LPWSTR) = 0;   // win8: set_ScreenSaver(LPWSTR)
  virtual HRESULT WINAPI get_VisualStyle2(LPWSTR*) = 0; // 1903: get_VisualStyleColor(LPWSTR*)
  virtual HRESULT WINAPI put_VisualStyle2(LPWSTR) = 0;  // 1903: put_VisualStyleColor(LPWSTR)

  // see "re" folder for full vtables

public:
  std::wstring GetDisplayName()
  {
    LPWSTR lpwstr = nullptr;
    const auto hr = get_DisplayName(&lpwstr);
    if(FAILED(hr) || !lpwstr)
    {
      WCHAR msg[64];
      wsprintf(msg, ESTRt(L"Error: %08X"), hr);
      return { msg };
    }
    std::wstring wstr{ lpwstr };
    SysFreeString(lpwstr);
    return wstr;
  }

  // we guess which one is the correct function, since it's vtable index shifted across windows versions
  HRESULT GetVisualStyle(std::wstring& path)
  {
    path.clear();
    LPWSTR lpwstr = nullptr;
    auto hr = get_VisualStyle2(&lpwstr);
    if(SUCCEEDED(hr) && lpwstr)
    {
      const auto lower = CharLowerW(SysAllocString(lpwstr));
      const auto is_style = wcsstr(lower, ESTRt(L"msstyles")) != nullptr;
      SysFreeString(lower);
      if(is_style)
      {
        path = lpwstr;
        SysFreeString(lpwstr);
        return hr;
      }
      SysFreeString(lpwstr);
    }
    lpwstr = nullptr;
    hr = get_VisualStyle(&lpwstr);
    if (SUCCEEDED(hr) && lpwstr)
    {
      const auto lower = CharLowerW(SysAllocString(lpwstr));
      const auto is_style = wcsstr(lower, ESTRt(L"msstyles")) != nullptr;
      SysFreeString(lower);
      if (is_style)
      {
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
MIDL_INTERFACE("{c1e8c83e-845d-4d95-81db-e283fdffc000}") IThemeManager2 : IUnknown
{
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
    THEME_APPLY_FLAGS apply_flags, // 0 when called in Windows
    THEMEPACK_FLAGS pack_flags // 0 when called in Windows
  ) = 0;
  virtual HRESULT WINAPI GetCustomTheme(int*) = 0;
  virtual HRESULT WINAPI GetDefaultTheme(int*) = 0;
  virtual HRESULT WINAPI CreateThemePack(HWND, LPCWSTR, THEMEPACK_FLAGS) = 0;
  virtual HRESULT WINAPI CloneAndSetCurrentTheme(HWND, LPCWSTR, LPWSTR*) = 0;
  virtual HRESULT WINAPI InstallThemePack(HWND, LPCWSTR, int, THEMEPACK_FLAGS, LPWSTR*, ITheme**) = 0;
  virtual HRESULT WINAPI DeleteTheme(LPCWSTR) = 0;
  virtual HRESULT WINAPI OpenTheme(HWND, LPCWSTR, THEMEPACK_FLAGS) = 0;
  virtual HRESULT WINAPI AddAndSelectTheme(HWND, LPCWSTR, THEME_APPLY_FLAGS, THEMEPACK_FLAGS) = 0;
  virtual HRESULT WINAPI SQMCurrentTheme() = 0;
  virtual HRESULT WINAPI ExportRoamingThemeToStream(IStream*, int) = 0;
  virtual HRESULT WINAPI ImportRoamingThemeFromStream(IStream*, int) = 0;
  virtual HRESULT WINAPI UpdateColorSettingsForLogonUI() = 0;
  virtual HRESULT WINAPI GetDefaultThemeId(GUID*) = 0;
  virtual HRESULT WINAPI UpdateCustomTheme() = 0;
};

const GUID CLSID_ThemeManager2 = { 0x9324da94, 0x50ec, 0x4a14, { 0xa7, 0x70, 0xe9, 0x0c, 0xa0, 0x3e, 0x7c, 0x8f } };
