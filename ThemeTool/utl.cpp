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
#include "pch.h"

#include "utl.h"

EXTERN_C_START

NTSYSAPI
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

// Last time instance wasn't just your own PE header's pointer was in 16 bit days.
HINSTANCE utl::get_instance() { return (HINSTANCE)&__ImageBase; }

static OBJECT_ATTRIBUTES make_object_attributes(
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

std::pair<const void*, size_t> utl::get_resource(WORD type, WORD id)
{
  const auto rc = FindResource(
    get_instance(),
    MAKEINTRESOURCE(id),
    MAKEINTRESOURCE(type)
  );
  if (!rc)
    return { nullptr, 0 };
  const auto rc_data = LoadResource(get_instance(), rc);
  const auto size = SizeofResource(get_instance(), rc);
  if (!rc_data)
    return { nullptr, 0 };
  const auto data = static_cast<const void*>(LockResource(rc_data));
  return { data, size };
}

// Returns native architecture, uses macros IMAGE_FILE_MACHINE_***
// May be wrong... who knows?? Probably not even Microsoft.
static USHORT get_native_architecture()
{
  // This is insanity

  static const auto architecture = []
  {
    typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS2) (HANDLE, PUSHORT, PUSHORT);

    const auto kernel32 = GetModuleHandleW(ESTRt(L"kernel32"));
    const auto pIsWow64Process2 = kernel32 ? (LPFN_ISWOW64PROCESS2)GetProcAddress(kernel32, ESTRt("IsWow64Process2")) : nullptr;
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

static int get_needed_dll_resource_id()
{
  switch (get_native_architecture())
  {
  case IMAGE_FILE_MACHINE_I386:
    return IDR_SECUREUXTHEME_DLL_X86;
  case IMAGE_FILE_MACHINE_AMD64:
    return IDR_SECUREUXTHEME_DLL_X64;
  case IMAGE_FILE_MACHINE_ARM64:
    return IDR_SECUREUXTHEME_DLL_ARM64;
  default:
    break;
  }
  return 0;
}

std::pair<const void*, size_t> utl::get_dll_blob()
{
  const auto id = get_needed_dll_resource_id();
  return id ? get_resource(256, id) : std::pair<const void*, size_t>{ nullptr, 0 };
}

bool utl::is_elevated()
{
  DWORD result = FALSE;
  HANDLE token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
  {
    TOKEN_ELEVATION elevation;
    DWORD size = sizeof(elevation);
    if (GetTokenInformation(
      token,
      TokenElevation,
      &elevation,
      sizeof(elevation),
      &size
    ))
      result = elevation.TokenIsElevated;

    CloseHandle(token);
  }
  return !!result;
}

const std::pair<std::wstring, std::wstring> utl::session_user()
{
  LPWSTR wtsinfo_ptr = nullptr;
  DWORD bytes_returned = 0;
  const auto success = WTSQuerySessionInformationW(
    WTS_CURRENT_SERVER_HANDLE,
    WTS_CURRENT_SESSION,
    WTSSessionInfo,
    &wtsinfo_ptr,
    &bytes_returned
  );
  if (success && wtsinfo_ptr)
  {
    const auto wtsinfo = (WTSINFOW*)wtsinfo_ptr;
    std::wstring username{ wtsinfo->UserName };
    std::wstring domain{ wtsinfo->Domain };
    WTSFreeMemory(wtsinfo_ptr);
    return std::make_pair(std::move(domain), std::move(username));
  }
  return {};
}

const std::pair<std::wstring, std::wstring> utl::process_user()
{
  std::pair<std::wstring, std::wstring> pair;
  HANDLE token = nullptr;
  if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
  {
    struct data_s
    {
      TOKEN_USER user;
      char data[0x800];
    } s;
    static_assert(offsetof(data_s, user) == 0, "this is not good");

    DWORD size = sizeof(s);
    auto success = GetTokenInformation(
      token,
      TokenUser,
      &s,
      sizeof(s),
      &size
    );
    if (success)
    {
      WCHAR username[USERNAME_LENGTH + 1]{};
      DWORD username_len = std::size(username);
      WCHAR domain[DOMAIN_LENGTH + 1]{};
      DWORD domain_len = std::size(domain);
      SID_NAME_USE name_use{};
      success = LookupAccountSidW(
        nullptr,
        s.user.User.Sid,
        username,
        &username_len,
        domain,
        &domain_len,
        &name_use
      );
      if (success)
        pair = std::pair<std::wstring, std::wstring>(domain, username);
    }
    CloseHandle(token);
  }
  return pair;
}

DWORD utl::read_file(std::wstring_view path, std::vector<char>& content)
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
      if(li.QuadPart <= 128 << 20) // max 128 MB for this api
      {
        content.resize((size_t)li.QuadPart);
        DWORD read = 0;
        const auto succeeded = ReadFile(
          file,
          content.data(),
          (size_t)li.QuadPart,
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

DWORD utl::write_file(std::wstring_view path, const void* data, size_t size)
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
      size,
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

DWORD utl::nuke_file(std::wstring_view path)
{
  if (DeleteFileW(path.data()))
    return NO_ERROR;

  // if the file doesn't exist just pretend we succeeded
  if (GetLastError() == ERROR_FILE_NOT_FOUND)
    return NO_ERROR;

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
  return NO_ERROR;
}

DWORD utl::open_key(PHKEY handle, const wchar_t* path, ULONG desired_access)
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

DWORD utl::rename_key(const wchar_t* old_path, const wchar_t* new_path)
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

DWORD utl::get_KnownDllPath(std::wstring& wstr)
{
  wstr.clear();
  DWORD error = NO_ERROR;
  auto attr = make_object_attributes(ESTRt(L"\\KnownDlls\\KnownDllPath"));
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

    if(NT_SUCCESS(status))
      wstr = path;
    else
      error = RtlNtStatusToDosError(status);

    NtClose(link);
  }
  else
    error = RtlNtStatusToDosError(status);

  return error;
}


std::wstring utl::ErrorToString(HRESULT error)
{
  wchar_t buf[0x1000];

  FormatMessageW(
    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    nullptr,
    error,
    MAKELANGID(LANG_USER_DEFAULT, SUBLANG_DEFAULT),
    buf,
    (DWORD)std::size(buf),
    nullptr
  );
  std::wstring wstr{ buf };
  const auto pos = wstr.find_last_not_of(L"\r\n");
  if (pos != std::wstring::npos)
    wstr.resize(pos);
  return wstr;
}