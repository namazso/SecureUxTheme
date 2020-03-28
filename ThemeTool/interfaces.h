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
#pragma once

enum THEME_MANAGER_INITIALIZATION_FLAGS : unsigned
{
  ThemeInitNoFlags = 0,
  ThemeInitFlagUnk0 = 1 << 0,
  ThemeInitFlagUnk1 = 1 << 1,
  ThemeInitFlagUnk2 = 1 << 2,
};

enum THEME_APPLY_FLAGS
{
  THEME_APPLY_FLAG_IGNORE_BACKGROUND    = 1 << 0,
  THEME_APPLY_FLAG_IGNORE_CURSOR        = 1 << 1,
  THEME_APPLY_FLAG_IGNORE_DESKTOP_ICONS = 1 << 2,
  THEME_APPLY_FLAG_IGNORE_COLOR         = 1 << 3,
  THEME_APPLY_FLAG_IGNORE_SOUND         = 1 << 4,
  // 1 << 5 seems to be unused
  THEME_APPLY_FLAG_UNKNOWN              = 1 << 6, // something about window metrics
  THEME_APPLY_FLAG_UNKNOWN2             = 1 << 7,
  THEME_APPLY_FLAG_NO_HOURGLASS         = 1 << 8
};

enum THEMEPACK_FLAGS
{
  THEMEPACK_FLAG_UNKNOWN = 3, // setting this seems to supress hourglass
  THEMEPACK_FLAG_UNKNOWN2 = 4 // something about RSS
};

enum DESKTOP_WALLPAPER_POSITION {};
enum tagTHEMECAT {};

struct ISlideshowSettings;

// const CThemeFile::`vftable'{for `ITheme'}
struct ITheme : IUnknown
{
  LPWSTR GetDisplayName()
  {
    LPWSTR lpwstr = nullptr;
    const auto hr = get_DisplayName(&lpwstr);
    if(FAILED(hr))
    {
      WCHAR msg[64];
      wsprintf(msg, L"Error: %08X", hr);
      lpwstr = SysAllocString(msg);
    }
    return lpwstr;
  }

  LPWSTR GetVisualStyle()
  {
    LPWSTR lpwstr = nullptr;
    auto hr = get_VisualStyle2(&lpwstr);
    if(SUCCEEDED(hr))
    {
      const auto lower = CharLowerW(SysAllocString(lpwstr));
      const auto is_style = wcsstr(lower, L"msstyles") != nullptr;
      SysFreeString(lower);
      if(is_style)
        return lpwstr;
      SysFreeString(lpwstr);
    }
    lpwstr = nullptr;
    hr = get_VisualStyle(&lpwstr);
    if (SUCCEEDED(hr))
    {
      const auto lower = CharLowerW(SysAllocString(lpwstr));
      const auto is_style = wcsstr(lower, L"msstyles") != nullptr;
      SysFreeString(lower);
      if (is_style)
        return lpwstr;
      SysFreeString(lpwstr);
      return SysAllocString(L"Error: Can't find get_VisualStyle");
    }

    WCHAR msg[64];
    wsprintf(msg, L"Error: %08X", hr);
    return SysAllocString(msg);
  }

private:
  virtual HRESULT WINAPI get_DisplayName(LPWSTR*) = 0;
  virtual HRESULT WINAPI put_DisplayName(LPWSTR) = 0;
  virtual HRESULT WINAPI get_VisualStyle(LPWSTR*) = 0;  // win8: get_ScreenSaver(LPWSTR*)
  virtual HRESULT WINAPI put_VisualStyle(LPWSTR) = 0;   // win8: set_ScreenSaver(LPWSTR)
  virtual HRESULT WINAPI get_VisualStyle2(LPWSTR*) = 0; // 1903: get_VisualStyleColor(LPWSTR*)
  virtual HRESULT WINAPI put_VisualStyle2(LPWSTR) = 0;  // 1903: put_VisualStyleColor(LPWSTR)
  // the rest changes across versions :(((
  /*virtual HRESULT WINAPI get_VisualStyle(LPWSTR*) = 0;
  virtual HRESULT WINAPI put_VisualStyle(LPWSTR) = 0;
  virtual HRESULT WINAPI get_VisualStyleColor(LPWSTR*) = 0;
  virtual HRESULT WINAPI put_VisualStyleColor(LPWSTR) = 0;
  virtual HRESULT WINAPI get_VisualStyleSize(LPWSTR*) = 0;
  virtual HRESULT WINAPI put_VisualStyleSize(LPWSTR) = 0;
  virtual HRESULT WINAPI get_VisualStyleVersion(int*) = 0;
  virtual HRESULT WINAPI put_VisualStyleVersion(int) = 0;
  virtual HRESULT WINAPI get_ColorizationColor(unsigned long*) = 0;
  virtual HRESULT WINAPI put_ColorizationColor(unsigned long) = 0;
  virtual HRESULT WINAPI get_ThemeId(GUID*) = 0;
  virtual HRESULT WINAPI put_ThemeId(GUID const&) = 0;
  // 1903+
  //virtual HRESULT WINAPI get_AppMode(int*) = 0;
  //virtual HRESULT WINAPI put_AppMode(int) = 0;
  //virtual HRESULT WINAPI get_SystemMode(int*) = 0;
  //virtual HRESULT WINAPI put_SystemMode(int) = 0;
  virtual HRESULT WINAPI get_Background(LPWSTR*) = 0;
  virtual HRESULT WINAPI put_Background(LPWSTR) = 0;
  virtual HRESULT WINAPI get_BackgroundPosition(DESKTOP_WALLPAPER_POSITION*) = 0;
  virtual HRESULT WINAPI put_BackgroundPosition(DESKTOP_WALLPAPER_POSITION) = 0;
  virtual HRESULT WINAPI get_BackgroundWriteTime(FILETIME*) = 0;
  virtual HRESULT WINAPI put_BackgroundWriteTime(FILETIME const*) = 0;
  virtual HRESULT WINAPI ClearBackgroundWriteTime() = 0;
  virtual HRESULT WINAPI get_SlideshowSettings(ISlideshowSettings**) = 0;
  virtual HRESULT WINAPI put_SlideshowSettings(ISlideshowSettings*) = 0;
  virtual HRESULT WINAPI get_SlideshowSourceDirectory(LPWSTR*) = 0;
  virtual HRESULT WINAPI put_SlideshowSourceDirectory(LPWSTR) = 0;
  virtual HRESULT WINAPI get_RSSFeed(LPWSTR*) = 0;
  virtual HRESULT WINAPI IsSlideshowEnabled(int*) = 0;
  virtual HRESULT WINAPI GetSlideshowSettingsWithoutFiles(ISlideshowSettings**) = 0;
  virtual HRESULT WINAPI GetPath(short, LPWSTR*) = 0;
  virtual HRESULT WINAPI SetPath(LPWSTR) = 0;
  virtual HRESULT WINAPI GetCursor(LPWSTR, LPWSTR*) = 0;
  virtual HRESULT WINAPI SetCursor(LPWSTR, LPWSTR) = 0;
  virtual HRESULT WINAPI GetSoundSchemeName(LPWSTR*) = 0;
  virtual HRESULT WINAPI SetSoundSchemeName(LPWSTR) = 0;
  virtual HRESULT WINAPI GetSound(LPWSTR, unsigned int, LPWSTR*) = 0;
  virtual HRESULT WINAPI SetSound(LPWSTR, LPWSTR) = 0;
  virtual HRESULT WINAPI GetAllSoundEvents(LPWSTR*) = 0;
  virtual HRESULT WINAPI GetDesktopIcon(LPWSTR, int, LPWSTR*) = 0;
  virtual HRESULT WINAPI GetDefaultDesktopIcon(LPWSTR, LPWSTR*) = 0;
  virtual HRESULT WINAPI SetDesktopIcon(LPWSTR, LPWSTR) = 0;
  virtual HRESULT WINAPI GetCategory(tagTHEMECAT*) = 0;
  virtual HRESULT WINAPI GetLogonBackgroundFlag(int*) = 0;
  virtual HRESULT WINAPI SetLogonBackgroundFlag() = 0;
  virtual HRESULT WINAPI ClearLogonBackgroundFlag() = 0;
  virtual HRESULT WINAPI GetAutoColorization(int*) = 0;
  virtual HRESULT WINAPI SetAutoColorization(int) = 0;
  virtual HRESULT WINAPI GetMultimonBackgroundsEnabled(int*) = 0;
  virtual HRESULT WINAPI SetMultimonBackgroundsEnabled(int) = 0;
  virtual HRESULT WINAPI GetMultimonBackground(unsigned int, LPWSTR*) = 0;
  virtual HRESULT WINAPI SetMultimonBackground(unsigned int, LPWSTR) = 0;
  virtual HRESULT WINAPI GetHighContrast(int*) = 0;
  virtual HRESULT WINAPI SetHighContrast(int) = 0;
  virtual HRESULT WINAPI GetThemeMagicValue(LPWSTR*) = 0;
  virtual HRESULT WINAPI SetThemeMagicValue(LPWSTR) = 0;
  virtual HRESULT WINAPI GetThemeColor(unsigned short const*, unsigned short**) = 0;
  virtual HRESULT WINAPI GetThemeImage(int, HBITMAP*) = 0;
  virtual HRESULT WINAPI GetWindowColorPreview(HBITMAP*) = 0;
  virtual HRESULT WINAPI GetBackgroundColor(unsigned long*) = 0;
  virtual HRESULT WINAPI GetColor(unsigned int, unsigned long*) = 0;
  virtual HRESULT WINAPI GetBrandLogo(LPWSTR*) = 0;
  virtual HRESULT WINAPI SetBrandLogo(LPWSTR) = 0;
  virtual HRESULT WINAPI ClearBrandLogo() = 0;
  virtual HRESULT WINAPI ClearScreenSaver() = 0;
  virtual HRESULT WINAPI GetScreenSaverName(LPWSTR*) = 0;
  virtual HRESULT WINAPI GetBackgroundPreview(HBITMAP*) = 0;
  virtual HRESULT WINAPI Copy(ITheme**) = 0;
  virtual HRESULT WINAPI SetThemeColor(unsigned short const*, unsigned long) = 0;*/
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
  /* this (hidden), parent, themeid, 1 (?), 0 (?), 0 (?) */
  virtual HRESULT WINAPI SetCurrentTheme(
    HWND parent,
    int theme_idx,
    int apply_now_not_only_registry,
    THEME_APPLY_FLAGS apply_flags,
    THEMEPACK_FLAGS pack_flags
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
