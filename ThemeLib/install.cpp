//  SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
//  Copyright (C) 2022  namazso <admin@namazso.eu>
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

#include "../public/secureuxtheme.h"
#include <winternl.h>
#include <random>
#include <unordered_map>

// using undocumented stuff is bad

EXTERN_C_START

NTSYSAPI
VOID
NTAPI
RtlGetNtVersionNumbers(
  _Out_opt_ PULONG NtMajorVersion,
  _Out_opt_ PULONG NtMinorVersion,
  _Out_opt_ PULONG NtBuildNumber
);

NTSYSAPI
NTSTATUS
NTAPI
RtlAdjustPrivilege(
  _In_ ULONG Privilege,
  _In_ BOOLEAN Enable,
  _In_ BOOLEAN Client,
  _Out_ PBOOLEAN WasEnabled
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenKey(
  _Out_ PHANDLE KeyHandle,
  _In_  ACCESS_MASK DesiredAccess,
  _In_  POBJECT_ATTRIBUTES ObjectAttributes
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtOpenSymbolicLinkObject(
  _Out_ PHANDLE LinkHandle,
  _In_ ACCESS_MASK DesiredAccess,
  _In_ POBJECT_ATTRIBUTES ObjectAttributes
);

NTSYSCALLAPI
NTSTATUS
NTAPI
NtQuerySymbolicLinkObject(
  _In_ HANDLE LinkHandle,
  _Inout_ PUNICODE_STRING LinkTarget,
  _Out_opt_ PULONG ReturnedLength
);

EXTERN_C_END

#define FLG_APPLICATION_VERIFIER (0x100)

static constexpr wchar_t kPatcherDllName[] = L"SecureUxTheme.dll";
static constexpr wchar_t kIFEO[] = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
static constexpr wchar_t kHKLMPrefix[] = L"\\Registry\\Machine\\";
static constexpr wchar_t kCurrentColorsPath[] = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\";
static constexpr wchar_t kCurrentColorsName[] = L"DefaultColors";
static constexpr wchar_t kCurrentColorsBackup[] = L"DefaultColors_backup";

static std::unordered_map<ULONG, std::pair<LPCVOID, SIZE_T>> g_dlls;

class unique_redirection_disabler
{
  PVOID OldValue{};
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

static bool IsLoadedInSession()
{
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

static bool IsInstalledForExecutable(const wchar_t* executable)
{
  const auto subkey = std::wstring{ kIFEO } + executable;
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

static DWORD InstallForExecutable(const wchar_t* executable)
{
  const auto subkey = std::wstring{ kIFEO } + executable;
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
  if (!ret)
  {
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

static DWORD UninstallForExecutable(const wchar_t* executable)
{
  const auto subkey = std::wstring{ kIFEO } + executable;
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
  if (!GlobalFlag)
  {
    ret = RegDeleteKeyValueW(
      HKEY_LOCAL_MACHINE,
      subkey.c_str(),
      L"GlobalFlag"
    );
  }
  else
  {
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
  if (!(GlobalFlag & FLG_APPLICATION_VERIFIER))
  {
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

// Returns native architecture, uses macros IMAGE_FILE_MACHINE_***
// May be wrong... who knows?? Probably not even Microsoft.
static USHORT GetNativeArchitecture()
{
  // This is insanity

  static const auto architecture = []
  {
    typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS2) (HANDLE, PUSHORT, PUSHORT);

    const auto kernel32 = GetModuleHandleW(L"kernel32");
    const auto pIsWow64Process2 = kernel32 ? (LPFN_ISWOW64PROCESS2)GetProcAddress(kernel32, "IsWow64Process2") : nullptr;
    USHORT ProcessMachine = 0;
    USHORT NativeMachine = 0;

    // Apparently IsWow64Process2 can fail somehow
    if (pIsWow64Process2 && pIsWow64Process2(GetCurrentProcess(), &ProcessMachine, &NativeMachine))
      return NativeMachine;

    SYSTEM_INFO si;
    // On 64 bit processors that aren't x64 or IA64, GetNativeSystemInfo behaves as GetSystemInfo
    GetNativeSystemInfo(&si);
    switch (si.wProcessorArchitecture)
    {
    case PROCESSOR_ARCHITECTURE_AMD64:
      return (USHORT)IMAGE_FILE_MACHINE_AMD64;
    case PROCESSOR_ARCHITECTURE_ARM:
      return (USHORT)IMAGE_FILE_MACHINE_ARM;
    case PROCESSOR_ARCHITECTURE_ARM64: // according to docs this could never happen
      return (USHORT)IMAGE_FILE_MACHINE_ARM64;
    case PROCESSOR_ARCHITECTURE_IA64:
      return (USHORT)IMAGE_FILE_MACHINE_IA64;
    case PROCESSOR_ARCHITECTURE_INTEL:
      return (USHORT)IMAGE_FILE_MACHINE_I386;
    default:
      break;
    }

    // I wonder why does IsWow64Process exist when GetNativeSystemInfo can provide same and more, plus it cannot fail
    // either unlike IsWow64Process which apparently can do so.

    return (USHORT)IMAGE_FILE_MACHINE_UNKNOWN;
  }();
  return architecture;
}

static OBJECT_ATTRIBUTES MakeObjectAttributes(
  const wchar_t* ObjectName,
  ULONG Attributes = OBJ_CASE_INSENSITIVE,
  HANDLE RootDirectory = nullptr,
  PSECURITY_DESCRIPTOR SecurityDescriptor = nullptr
)
{
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

static DWORD GetKnownDllPath(std::wstring& wstr)
{
  wstr.clear();
  DWORD error = NO_ERROR;
  auto attr = MakeObjectAttributes(L"\\KnownDlls\\KnownDllPath");
  HANDLE link = nullptr;
  auto status = NtOpenSymbolicLinkObject(&link, GENERIC_READ, &attr);
  if (NT_SUCCESS(status))
  {
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
  }
  else
    error = RtlNtStatusToDosError(status);

  return error;
}

static DWORD GetPatcherDllPath(std::wstring& path)
{
  path = {};
  const auto status = GetKnownDllPath(path);
  if (status != ERROR_SUCCESS)
    return status;

  path += L"\\";
  path += kPatcherDllName;
  return ERROR_SUCCESS;
}

static std::pair<LPCVOID, SIZE_T> GetBlob()
{
  const auto entry = g_dlls.find(GetNativeArchitecture());
  return entry == g_dlls.end() ? std::pair<LPCVOID, SIZE_T>{ nullptr, 0 } : entry->second;
}

DWORD open_key(PHKEY handle, const wchar_t* path, ULONG desired_access)
{
  UNICODE_STRING ustr{};
  RtlInitUnicodeString(&ustr, path);
  OBJECT_ATTRIBUTES attr{};
  InitializeObjectAttributes(
    &attr,
    &ustr,
    OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
    nullptr,
    nullptr
  );
  auto status = NtOpenKey(
    (PHANDLE)handle,
    desired_access | KEY_WOW64_64KEY,
    &attr
  );

  return RtlNtStatusToDosError(status);
}

DWORD rename_key(const wchar_t* old_path, const wchar_t* new_path)
{
  HKEY key{};
  const auto ret = open_key(&key, old_path, KEY_ALL_ACCESS);

  if (ret)
    return ret;

  UNICODE_STRING ustr{};
  RtlInitUnicodeString(&ustr, new_path);
  const auto status = NtRenameKey(
    key,
    &ustr
  );

  NtClose(key);

  return RtlNtStatusToDosError(status);
}


static DWORD read_file(std::wstring_view path, std::vector<uint8_t>& content)
{
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
  if (file != INVALID_HANDLE_VALUE)
  {
    LARGE_INTEGER li{};
    if (GetFileSizeEx(file, &li))
    {
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
      }
      else
        error = GetLastError();
    }
    else
      error = GetLastError();

    CloseHandle(file);
  }
  else
    error = GetLastError();

  if (error)
    content.clear();
  return error;
}

static DWORD write_file(std::wstring_view path, const void* data, size_t size)
{
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
  if (file != INVALID_HANDLE_VALUE)
  {
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
  }
  else
    error = GetLastError();

  return error;
}

static DWORD nuke_file(std::wstring_view path)
{
  if (DeleteFileW(path.data()))
    return ERROR_SUCCESS;

  // if the file doesn't exist just pretend we succeeded
  if (GetLastError() == ERROR_FILE_NOT_FOUND)
    return ERROR_SUCCESS;

  std::wstring wstr{ path.data(), path.size() };
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

void secureuxtheme_set_dll_for_arch(LPCVOID data, SIZE_T size, ULONG arch)
{
  g_dlls[arch] = { data, size };
}

ULONG secureuxtheme_get_state_flags()
{
  unique_redirection_disabler _disabler{};
  ULONG flags = 0;
  if (IsLoadedInSession())
    flags |= SECUREUXTHEME_STATE_LOADED;
  std::wstring path{};
  auto res = GetPatcherDllPath(path);
  if (res == ERROR_SUCCESS)
  {
    std::vector<uint8_t> content;
    res = read_file(path, content);
    if (res == ERROR_SUCCESS && !content.empty() && IsInstalledForExecutable(L"winlogon.exe"))
    {
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

static bool IsValidDefaultColors(const wchar_t* default_colors)
{
  DWORD ActiveTitle{};
  DWORD ActiveTitle_size{ sizeof(ActiveTitle) };
  return ERROR_SUCCESS == RegGetValueW(
    HKEY_LOCAL_MACHINE,
    (std::wstring{ kCurrentColorsPath } + default_colors + L"\\Standard").c_str(),
    L"ActiveTitle",
    RRF_RT_REG_DWORD | RRF_ZEROONFAILURE,
    nullptr,
    &ActiveTitle,
    &ActiveTitle_size
  );
}

static HRESULT RenameDefaultColors()
{
  const auto current_valid = IsValidDefaultColors(kCurrentColorsName);
  
  if (current_valid)
  {
    // we need to do something about current one.

    // delete backup if any exists for good measure
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, (std::wstring{ kCurrentColorsPath } + kCurrentColorsBackup).c_str());
    
    const auto result = rename_key(
      (std::wstring{ kHKLMPrefix } + kCurrentColorsPath + kCurrentColorsName).c_str(),
      kCurrentColorsBackup
    );
    if (result != ERROR_SUCCESS && result != ERROR_FILE_NOT_FOUND)
      return HRESULT_FROM_WIN32(result);
  }
  HKEY result;
  result = nullptr;
  RegCreateKeyW(HKEY_LOCAL_MACHINE, (std::wstring{ kCurrentColorsPath } + kCurrentColorsName).c_str(), &result);
  RegCloseKey(result);
  result = nullptr;
  RegCreateKeyW(HKEY_LOCAL_MACHINE, (std::wstring{ kCurrentColorsPath } + kCurrentColorsName + L"\\HighContrast").c_str(), &result);
  RegCloseKey(result);
  result = nullptr;
  RegCreateKeyW(HKEY_LOCAL_MACHINE, (std::wstring{ kCurrentColorsPath } + kCurrentColorsName + L"\\Standard").c_str(), &result);
  RegCloseKey(result);
  result = nullptr;
  return S_OK;
}

static HRESULT RestoreDefaultColors()
{
  // We ignore failures here because it's not a big edeal

  const auto current_valid = IsValidDefaultColors(kCurrentColorsName);
  const auto backup_valid = IsValidDefaultColors(kCurrentColorsBackup);
  if (backup_valid && !current_valid)
  {
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, (std::wstring{ kCurrentColorsPath } + kCurrentColorsName).c_str());
    rename_key(
      (std::wstring{ kHKLMPrefix } + kCurrentColorsPath + kCurrentColorsBackup).c_str(),
      kCurrentColorsName
    );
  }
  return S_OK;
}

static HRESULT InstallInternal(ULONG install_flags)
{
  const auto blob = GetBlob();
  if (!blob.first)
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

  if (install_flags & SECUREUXTHEME_INSTALL_HOOK_EXPLORER)
  {
    res = InstallForExecutable(L"explorer.exe");
    if (res != ERROR_SUCCESS)
      return HRESULT_FROM_WIN32(res);
  }

  if (install_flags & SECUREUXTHEME_INSTALL_HOOK_SETTINGS)
  {
    res = InstallForExecutable(L"SystemSettings.exe");
    if (res != ERROR_SUCCESS)
      return HRESULT_FROM_WIN32(res);
  }

  if (install_flags & SECUREUXTHEME_INSTALL_HOOK_LOGONUI)
  {
    res = InstallForExecutable(L"LogonUI.exe");
    if (res != ERROR_SUCCESS)
      return HRESULT_FROM_WIN32(res);
  }

  if (install_flags & SECUREUXTHEME_INSTALL_RENAME_DEFAULTCOLORS)
  {
    hr = RenameDefaultColors();
    if (FAILED(hr))
      return hr;
  }

  return S_OK;
}

HRESULT secureuxtheme_install(ULONG install_flags)
{
  unique_redirection_disabler _disabler{};
  const auto hr = InstallInternal(install_flags);
  if (FAILED(hr))
    secureuxtheme_uninstall();
  return hr;
}

HRESULT secureuxtheme_uninstall()
{
  unique_redirection_disabler _disabler{};
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

  const auto hr = RestoreDefaultColors();
  if (FAILED(hr))
    return hr;

  return S_OK;
}

HRESULT secureuxtheme_hook_add(LPCWSTR executable)
{
  unique_redirection_disabler _disabler{};
  return HRESULT_FROM_WIN32(InstallForExecutable(executable));
}

HRESULT secureuxtheme_hook_remove(LPCWSTR executable)
{
  unique_redirection_disabler _disabler{};
  return HRESULT_FROM_WIN32(UninstallForExecutable(executable));
}

BOOLEAN secureuxtheme_hook_test(LPCWSTR executable)
{
  unique_redirection_disabler _disabler{};
  return IsInstalledForExecutable(executable) ? TRUE : FALSE;
}
