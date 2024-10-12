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

#define PHNT_VERSION PHNT_WINBLUE

#include <phnt_windows.h>

#include <phnt.h>

#include <secureuxtheme.h>

#include <random>
#include <unordered_map>

static constexpr wchar_t kPatcherDllName[] = L"SecureUxTheme.dll";
static constexpr wchar_t kIFEO[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";

static constexpr uint8_t kDLL[] = {
#include <SecureUxTheme.dll.h>
};

static bool IsLoadedInSession() {
  const auto h = OpenEventW(
    SYNCHRONIZE,
    FALSE,
    L"SecureUxTheme_Loaded"
  );
  if (!h)
    return GetLastError() == ERROR_ACCESS_DENIED; // honestly, i have no idea how to set up permissions when creating it
  CloseHandle(h);
  return true;
}

static bool IsInstalledForExecutable(const wchar_t* executable) {
  const auto subkey = std::wstring{kIFEO} + executable;
  DWORD GlobalFlag = 0;
  DWORD GlobalFlag_size = sizeof(GlobalFlag);
  RegGetValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    L"GlobalFlag",
    RRF_RT_REG_DWORD | RRF_ZEROONFAILURE,
    nullptr,
    &GlobalFlag,
    &GlobalFlag_size
  );
  wchar_t VerifierDlls[257]{};
  DWORD VerifierDlls_size = sizeof(VerifierDlls);
  RegGetValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    L"VerifierDlls",
    RRF_RT_REG_SZ | RRF_ZEROONFAILURE,
    nullptr,
    VerifierDlls,
    &VerifierDlls_size
  );
  VerifierDlls[256] = 0;
  return GlobalFlag & FLG_APPLICATION_VERIFIER && 0 == _wcsicmp(VerifierDlls, kPatcherDllName);
}

static DWORD InstallForExecutable(const wchar_t* executable) {
  const auto subkey = std::wstring{kIFEO} + executable;
  DWORD GlobalFlag = 0;
  DWORD GlobalFlag_size = sizeof(GlobalFlag);
  // we don't care if it fails
  RegGetValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    L"GlobalFlag",
    RRF_RT_REG_DWORD | RRF_ZEROONFAILURE,
    nullptr,
    &GlobalFlag,
    &GlobalFlag_size
  );
  GlobalFlag |= FLG_APPLICATION_VERIFIER;
  auto ret = RegSetKeyValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    L"GlobalFlag",
    REG_DWORD,
    &GlobalFlag,
    sizeof(GlobalFlag)
  );
  if (!ret) {
    ret = RegSetKeyValueW(
      HKEY_LOCAL_MACHINE,
      subkey.c_str(),
      L"VerifierDlls",
      REG_SZ,
      kPatcherDllName,
      sizeof(kPatcherDllName)
    );
  }
  return ret;
}

static DWORD UninstallForExecutable(const wchar_t* executable) {
  const auto subkey = std::wstring{kIFEO} + executable;
  DWORD GlobalFlag = 0;
  DWORD GlobalFlag_size = sizeof(GlobalFlag);
  // we don't care if it fails
  RegGetValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    L"GlobalFlag",
    RRF_RT_REG_DWORD | RRF_ZEROONFAILURE,
    nullptr,
    &GlobalFlag,
    &GlobalFlag_size
  );
  GlobalFlag &= ~FLG_APPLICATION_VERIFIER;
  DWORD ret = ERROR_SUCCESS;
  if (!GlobalFlag) {
    ret = RegDeleteKeyValueW(
      HKEY_LOCAL_MACHINE,
      subkey.c_str(),
      L"GlobalFlag"
    );
  } else {
    ret = RegSetKeyValueW(
      HKEY_LOCAL_MACHINE,
      subkey.c_str(),
      L"GlobalFlag",
      REG_DWORD,
      &GlobalFlag,
      sizeof(GlobalFlag)
    );
  }

  // query it again, so we don't delete the other key if we failed removing the flag somehow, that would login loop
  GlobalFlag_size = sizeof(GlobalFlag);
  RegGetValueW(
    HKEY_LOCAL_MACHINE,
    subkey.c_str(),
    L"GlobalFlag",
    RRF_RT_REG_DWORD | RRF_ZEROONFAILURE,
    nullptr,
    &GlobalFlag,
    &GlobalFlag_size
  );
  if (!(GlobalFlag & FLG_APPLICATION_VERIFIER)) {
    // FLG_APPLICATION_VERIFIER is not set, we don't care how we got here, nor if we succeed deleting VerifierDlls
    ret = ERROR_SUCCESS;

    RegDeleteKeyValueW(
      HKEY_LOCAL_MACHINE,
      subkey.c_str(),
      L"VerifierDlls"
    );
  }

  return ret;
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

static OBJECT_ATTRIBUTES MakeObjectAttributes(
  const wchar_t* ObjectName,
  ULONG Attributes = OBJ_CASE_INSENSITIVE,
  HANDLE RootDirectory = nullptr,
  PSECURITY_DESCRIPTOR SecurityDescriptor = nullptr
) {
  OBJECT_ATTRIBUTES a;
  UNICODE_STRING ustr;
  RtlInitUnicodeString(&ustr, ObjectName);
  InitializeObjectAttributes(
    &a,
    &ustr,
    Attributes,
    RootDirectory,
    SecurityDescriptor
  );
  return a;
}

static DWORD GetKnownDllPath(std::wstring& wstr) {
  wstr.clear();
  DWORD error = NO_ERROR;
  auto attr = MakeObjectAttributes(L"\\KnownDlls\\KnownDllPath");
  HANDLE link = nullptr;
  auto status = NtOpenSymbolicLinkObject(&link, GENERIC_READ, &attr);
  if (NT_SUCCESS(status)) {
    wchar_t path[260]{};
    UNICODE_STRING ustr{};
    ustr.Buffer = path;
    ustr.MaximumLength = sizeof(path) - sizeof(wchar_t);
    ULONG returned_length = sizeof(path) - sizeof(wchar_t);
    status = NtQuerySymbolicLinkObject(link, &ustr, &returned_length);

    if (NT_SUCCESS(status))
      wstr = path;
    else
      error = RtlNtStatusToDosError(status);

    NtClose(link);
  } else
    error = RtlNtStatusToDosError(status);

  return error;
}

static DWORD GetPatcherDllPath(std::wstring& path) {
  path = {};
  const auto status = GetKnownDllPath(path);
  if (status != ERROR_SUCCESS)
    return status;

  path += L"\\";
  path += kPatcherDllName;
  return ERROR_SUCCESS;
}

static std::pair<LPCVOID, SIZE_T> GetBlob() {
  return { std::begin(kDLL), std::size(kDLL) };
}

static DWORD read_file(std::wstring_view path, std::vector<uint8_t>& content) {
  content.clear();
  DWORD error = NO_ERROR;
  const auto file = CreateFileW(
    path.data(),
    FILE_READ_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    nullptr,
    OPEN_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    nullptr
  );
  if (file != INVALID_HANDLE_VALUE) {
    LARGE_INTEGER li{};
    if (GetFileSizeEx(file, &li)) {
      if (li.QuadPart <= 128 << 20) // max 128 MB for this api
      {
        content.resize((size_t)li.QuadPart);
        DWORD read = 0;
        const auto succeeded = ReadFile(
          file,
          content.data(),
          (DWORD)li.QuadPart,
          &read,
          nullptr
        );
        if (!succeeded || read != li.QuadPart)
          error = GetLastError();
      } else
        error = GetLastError();
    } else
      error = GetLastError();

    CloseHandle(file);
  } else
    error = GetLastError();

  if (error)
    content.clear();
  return error;
}

static DWORD write_file(std::wstring_view path, const void* data, size_t size) {
  DWORD error = NO_ERROR;
  const auto file = CreateFileW(
    path.data(),
    FILE_WRITE_DATA,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    nullptr,
    CREATE_ALWAYS,
    FILE_ATTRIBUTE_NORMAL,
    nullptr
  );
  if (file != INVALID_HANDLE_VALUE) {
    DWORD written = 0;
    const auto succeeded = WriteFile(
      file,
      data,
      (DWORD)size,
      &written,
      nullptr
    );
    if (!succeeded || written != size)
      error = GetLastError();

    CloseHandle(file);
  } else
    error = GetLastError();

  return error;
}

static DWORD nuke_file(std::wstring_view path) {
  if (DeleteFileW(path.data()))
    return ERROR_SUCCESS;

  // if the file doesn't exist just pretend we succeeded
  if (GetLastError() == ERROR_FILE_NOT_FOUND)
    return ERROR_SUCCESS;

  std::wstring wstr{path.data(), path.size()};
  {
    // cryptographically secure random for filenames!
    std::random_device dev{};
    wstr += L'.';
    for (auto i = 0; i < 8; ++i) // 8 random cyrillic chars
      wstr += (wchar_t)(0x0400 | (dev() & 0xFF));
  }
  if (!MoveFileExW(path.data(), wstr.data(), 0))
    return GetLastError();

  MoveFileExW(wstr.data(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);

  // we don't care if actual deleting succeeded, the file is moved away anyways
  return ERROR_SUCCESS;
}

ULONG secureuxtheme_get_state_flags() {
  ULONG flags = 0;
  if (IsLoadedInSession())
    flags |= SECUREUXTHEME_STATE_LOADED;
  std::wstring path{};
  auto res = GetPatcherDllPath(path);
  if (res == ERROR_SUCCESS) {
    std::vector<uint8_t> content;
    res = read_file(path, content);
    if (res == ERROR_SUCCESS && !content.empty() && IsInstalledForExecutable(L"winlogon.exe")) {
      flags |= SECUREUXTHEME_STATE_INSTALLED;
      const auto blob = GetBlob();
      if (blob.first && content.size() == blob.second && 0 == memcmp(content.data(), blob.first, content.size()))
        flags |= SECUREUXTHEME_STATE_CURRENT;
      if (IsInstalledForExecutable(L"explorer.exe"))
        flags |= SECUREUXTHEME_STATE_EXPLORER_HOOKED;
      if (IsInstalledForExecutable(L"LogonUI.exe"))
        flags |= SECUREUXTHEME_STATE_LOGONUI_HOOKED;
      if (IsInstalledForExecutable(L"SystemSettings.exe"))
        flags |= SECUREUXTHEME_STATE_SETTINGS_HOOKED;
    }
  }
  return flags;
}

static HRESULT DeleteDefaultColors() {
  UNICODE_STRING name{};
  OBJECT_ATTRIBUTES attr{};

  RtlInitUnicodeString(&name, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\DefaultColors\\Standard");
  InitializeObjectAttributes(&attr, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

  HANDLE standard{};
  NtOpenKey(&standard, KEY_SET_VALUE, &attr);

  RtlInitUnicodeString(&name, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\DefaultColors\\HighContrast");
  InitializeObjectAttributes(&attr, &name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

  HANDLE high_contrast{};
  NtOpenKey(&high_contrast, KEY_SET_VALUE, &attr);

  if (!standard && !high_contrast)
    return S_OK;

  static constexpr const wchar_t* colors[] = {
    L"ActiveTitle",
    L"ButtonFace",
    L"ButtonText",
    L"GrayText",
    L"Hilight",
    L"HilightText",
    L"HotTrackingColor",
    L"InactiveTitle",
    L"InactiveTitleText",
    L"MenuHilight",
    L"TitleText",
    L"Window",
    L"WindowText"
  };

  for (auto color : colors) {
    UNICODE_STRING value{};
    RtlInitUnicodeString(&value, color);
    if (standard)
      NtDeleteValueKey(standard, &value);
    if (high_contrast)
      NtDeleteValueKey(high_contrast, &value);
  }

  if (standard)
    NtClose(standard);
  if (high_contrast)
    NtClose(high_contrast);

  return S_OK;
}

static HRESULT InstallInternal(ULONG install_flags) {
  const auto blob = GetBlob();
  const auto nth = RtlImageNtHeader((PVOID)blob.first);
  if (nth->FileHeader.Machine != GetNativeArchitecture())
    return HRESULT_FROM_WIN32(ERROR_INSTALL_WRONG_PROCESSOR_ARCHITECTURE);

  auto hr = secureuxtheme_uninstall();
  if (FAILED(hr))
    return hr;

  std::wstring path{};
  auto res = GetPatcherDllPath(path);
  if (res != ERROR_SUCCESS)
    return HRESULT_FROM_WIN32(res);

  res = write_file(path, blob.first, blob.second);
  if (res != ERROR_SUCCESS)
    return HRESULT_FROM_WIN32(res);

  res = InstallForExecutable(L"winlogon.exe");
  if (res != ERROR_SUCCESS)
    return HRESULT_FROM_WIN32(res);

  if (install_flags & SECUREUXTHEME_INSTALL_HOOK_EXPLORER) {
    res = InstallForExecutable(L"explorer.exe");
    if (res != ERROR_SUCCESS)
      return HRESULT_FROM_WIN32(res);
  }

  if (install_flags & SECUREUXTHEME_INSTALL_HOOK_SETTINGS) {
    res = InstallForExecutable(L"SystemSettings.exe");
    if (res != ERROR_SUCCESS)
      return HRESULT_FROM_WIN32(res);
  }

  if (install_flags & SECUREUXTHEME_INSTALL_HOOK_LOGONUI) {
    res = InstallForExecutable(L"LogonUI.exe");
    if (res != ERROR_SUCCESS)
      return HRESULT_FROM_WIN32(res);
  }

  if (install_flags & SECUREUXTHEME_INSTALL_DELETE_DEFAULTCOLORS) {
    hr = DeleteDefaultColors();
    if (FAILED(hr))
      return hr;
  }

  return S_OK;
}

HRESULT secureuxtheme_install(ULONG install_flags) {
  const auto hr = InstallInternal(install_flags);
  if (FAILED(hr))
    secureuxtheme_uninstall();
  return hr;
}

HRESULT secureuxtheme_uninstall() {
  auto res = UninstallForExecutable(L"winlogon.exe");
  if (res != ERROR_SUCCESS)
    return HRESULT_FROM_WIN32(res);

  res = UninstallForExecutable(L"explorer.exe");
  if (res != ERROR_SUCCESS)
    return HRESULT_FROM_WIN32(res);

  res = UninstallForExecutable(L"SystemSettings.exe");
  if (res != ERROR_SUCCESS)
    return HRESULT_FROM_WIN32(res);

  res = UninstallForExecutable(L"LogonUI.exe");
  if (res != ERROR_SUCCESS)
    return HRESULT_FROM_WIN32(res);

  res = UninstallForExecutable(L"dwm.exe");
  if (res != ERROR_SUCCESS)
    return HRESULT_FROM_WIN32(res);

  // at this point we removed all the hooks, we can delete the file

  std::wstring path{};
  res = GetPatcherDllPath(path);
  if (res != ERROR_SUCCESS)
    return HRESULT_FROM_WIN32(res);
  res = nuke_file(path);
  if (res != ERROR_SUCCESS)
    return HRESULT_FROM_WIN32(res);

  return S_OK;
}

HRESULT secureuxtheme_hook_add(LPCWSTR executable) {
  return HRESULT_FROM_WIN32(InstallForExecutable(executable));
}

HRESULT secureuxtheme_hook_remove(LPCWSTR executable) {
  return HRESULT_FROM_WIN32(UninstallForExecutable(executable));
}

BOOLEAN secureuxtheme_hook_test(LPCWSTR executable) {
  return IsInstalledForExecutable(executable) ? TRUE : FALSE;
}
