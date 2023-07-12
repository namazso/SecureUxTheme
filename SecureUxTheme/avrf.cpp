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

#ifndef _NO_CRT_STDIO_INLINE
#define _NO_CRT_STDIO_INLINE 1
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

// Make debug builds link. Debugging sucks either way
#ifdef _ITERATOR_DEBUG_LEVEL
#undef _ITERATOR_DEBUG_LEVEL
#endif
#define _ITERATOR_DEBUG_LEVEL 0

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#include <WinCrypt.h>
#include <delayloadhandler.h>

// See AVRF.md to get how this thing works

// Semi-private ntapi stuff

EXTERN_C_START

#define DLL_PROCESS_VERIFIER 4

using RTL_VERIFIER_DLL_LOAD_CALLBACK = VOID(NTAPI *) (PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);
using RTL_VERIFIER_DLL_UNLOAD_CALLBACK = VOID(NTAPI *) (PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);
using RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK = VOID(NTAPI *) (PVOID AllocationBase, SIZE_T AllocationSize);

typedef struct _RTL_VERIFIER_THUNK_DESCRIPTOR {
  PCSTR ThunkName;
  PVOID ThunkOldAddress;
  PVOID ThunkNewAddress;
} RTL_VERIFIER_THUNK_DESCRIPTOR, *PRTL_VERIFIER_THUNK_DESCRIPTOR;

typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR {
  PCWSTR  DllName;
  DWORD   DllFlags;
  PVOID   DllAddress;
  PRTL_VERIFIER_THUNK_DESCRIPTOR  DllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR, *PRTL_VERIFIER_DLL_DESCRIPTOR;

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR {
  DWORD   Length;
  PRTL_VERIFIER_DLL_DESCRIPTOR      ProviderDlls;
  RTL_VERIFIER_DLL_LOAD_CALLBACK    ProviderDllLoadCallback;
  RTL_VERIFIER_DLL_UNLOAD_CALLBACK  ProviderDllUnloadCallback;
  PCWSTR  VerifierImage;
  DWORD   VerifierFlags;
  DWORD   VerifierDebug;
  PVOID   RtlpGetStackTraceAddress;
  PVOID   RtlpDebugPageHeapCreate;
  PVOID   RtlpDebugPageHeapDestroy;
  RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK ProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR, *PRTL_VERIFIER_PROVIDER_DESCRIPTOR;

NTSYSAPI
NTSTATUS
NTAPI
LdrDisableThreadCalloutsForDll(
  _In_  PVOID DllImageBase
);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetProcedureAddress(
  _In_	PVOID BaseAddress,
  _In_	PANSI_STRING Name,
  _In_	ULONG Ordinal,
  _Out_	PVOID *ProcedureAddress
);

NTSYSAPI
PVOID
NTAPI
RtlPcToFileHeader(
  _In_  PVOID PcValue,
  _Out_ PVOID* BaseOfImage
);

NTSYSAPI
NTSTATUS
NTAPI
LdrGetDllHandle(
  _In_opt_	PWSTR DllPath,
  _In_opt_	PULONG DllCharacteristics,
  _In_		PUNICODE_STRING DllName,
  _Out_		PVOID* DllHandle
);

NTSYSAPI
ULONG
DbgPrintEx(
  ULONG ComponentId,
  ULONG Level,
  PCSTR Format,
  ...
);

NTSYSAPI
NTSTATUS
NTAPI
NtProtectVirtualMemory(
  _In_	  HANDLE  ProcessHandle,
  _Inout_ PVOID   *BaseAddress,
  _Inout_ PSIZE_T RegionSize,
  _In_    ULONG   NewProtect,
  _Out_   PULONG  OldProtect
);

typedef enum _EVENT_TYPE
{
  NotificationEvent,
  SynchronizationEvent
} EVENT_TYPE;

NTSYSAPI
NTSTATUS
NTAPI
NtCreateEvent(
  _Out_     PHANDLE EventHandle,
  _In_      ACCESS_MASK DesiredAccess,
  _In_opt_  POBJECT_ATTRIBUTES ObjectAttributes,
  _In_      EVENT_TYPE EventType,
  _In_      BOOLEAN InitialState
);

NTSYSAPI
NTSTATUS
NTAPI
RtlGetTokenNamedObjectPath(
  _In_      HANDLE Token,
  _In_opt_  PSID Sid,
  _Out_     PUNICODE_STRING ObjectPath
);

NTSYSAPI
NTSTATUS
NTAPI
NtOpenProcessToken(
  _In_  HANDLE ProcessHandle,
  _In_  ACCESS_MASK DesiredAccess,
  _Out_ PHANDLE TokenHandle
);

NTSYSAPI
NTSTATUS
NTAPI
NtQueryInformationToken(
  _In_ HANDLE TokenHandle,
  _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
  _Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
  _In_ ULONG TokenInformationLength,
  _Out_ PULONG ReturnLength
);

NTSYSAPI
NTSTATUS
NTAPI
RtlAppendUnicodeToString(
  _In_      PUNICODE_STRING Destination,
  _In_opt_  PCWSTR Source
);

typedef PVOID(NTAPI *PDELAYLOAD_FAILURE_SYSTEM_ROUTINE)(
  _In_ PCSTR DllName,
  _In_ PCSTR ProcName
  );

#define RTL_CONSTANT_STRING(s) { \
  sizeof(s) - sizeof((s)[0]), \
  sizeof(s), \
  (std::add_pointer_t<std::remove_const_t<std::remove_pointer_t<std::decay_t<decltype(s)>>>>)(s) \
}

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define NtCurrentThread() ((HANDLE)(LONG_PTR)-2)
#define NtCurrentSession() ((HANDLE)(LONG_PTR)-3)
#define NtCurrentProcessToken() ((HANDLE)(LONG_PTR)-4)
#define NtCurrentThreadToken() ((HANDLE)(LONG_PTR)-5)

EXTERN_C_END

// I don't believe in comments

#include <cstring>
#include <type_traits>
#include <algorithm>

#if defined(_DEBUG)
#	define DebugPrint(str, ...) DbgPrintEx((ULONG)101u, 3u, "[SecureUxTheme] " __FUNCTION__ ": " str, ## __VA_ARGS__)
#else
#	define DebugPrint(str, ...)
#endif

BOOL
WINAPI
CryptVerifySignatureW_Hook(
  _In_                        HCRYPTHASH  hHash,
  _In_reads_bytes_(dwSigLen)  CONST BYTE  *pbSignature,
  _In_                        DWORD       dwSigLen,
  _In_                        HCRYPTKEY   hPubKey,
  _In_opt_                    LPCWSTR     szDescription,
  _In_                        DWORD       dwFlags
);

PVOID
WINAPI
ResolveDelayLoadedAPI_Hook(
  _In_       PVOID                             ParentModuleBase,
  _In_       PCIMAGE_DELAYLOAD_DESCRIPTOR      DelayloadDescriptor,
  _In_opt_   PDELAYLOAD_FAILURE_DLL_CALLBACK   FailureDllHook,
  _In_opt_   PDELAYLOAD_FAILURE_SYSTEM_ROUTINE FailureSystemHook,
  _Out_      PIMAGE_THUNK_DATA                 ThunkAddress,
  _Reserved_ ULONG                             Flags
);

BOOL
WINAPI
SetSysColors_Hook(
  _In_                  int             cElements,
  _In_reads_(cElements) CONST INT       *lpaElements,
  _In_reads_(cElements) CONST COLORREF  *lpaRgbValues
);

struct hook_entry
{
  ANSI_STRING     function_name;
  PVOID           old_address;
  PVOID           new_address;
};

struct hook_target_image
{
  UNICODE_STRING  name;
  ULONG           hook_bitmap;
  PVOID           base = nullptr;
};

#define DEFINE_HOOK(name) {RTL_CONSTANT_STRING(#name), nullptr, (PVOID)&name ## _Hook}

static hook_entry s_hooks[] =
{
  DEFINE_HOOK(CryptVerifySignatureW),
  DEFINE_HOOK(ResolveDelayLoadedAPI),
  DEFINE_HOOK(SetSysColors),
};

static hook_target_image s_target_images[] =
{
  { RTL_CONSTANT_STRING(L"themeui"),          0b011 },
  { RTL_CONSTANT_STRING(L"themeservice"),     0b011 },
  { RTL_CONSTANT_STRING(L"uxinit"),           0b011 },
  { RTL_CONSTANT_STRING(L"uxtheme"),          0b011 },
  { RTL_CONSTANT_STRING(L"logoncontroller"),  0b110 },
};

void* get_original_from_hook_address(void* hook_address)
{
  const auto it = std::find_if(std::begin(s_hooks), std::end(s_hooks), [hook_address](const hook_entry& e)
  {
    return e.new_address == hook_address;
  });

  return it == std::end(s_hooks) ? nullptr : it->old_address;
}

template <typename T>
T* get_original_from_hook_address_wrapper(T* fn)
{
  return (T*)get_original_from_hook_address((void*)fn);
}

void signal_loaded()
{
  ULONG id{};
  ULONG ret_len{};
  auto status = NtQueryInformationToken(NtCurrentProcessToken(), TokenSessionId, &id, sizeof(id), &ret_len);
  if (!NT_SUCCESS(status))
    return;

  wchar_t full_name[128];
  swprintf_s(full_name, L"\\Sessions\\%lu\\BaseNamedObjects\\SecureUxTheme_Loaded", id);

  UNICODE_STRING name;
  RtlInitUnicodeString(&name, full_name);

  OBJECT_ATTRIBUTES attr;
  InitializeObjectAttributes(
    &attr,
    &name,
    0,
    nullptr,
    nullptr
  );
  HANDLE event_handle = nullptr;
  NtCreateEvent(
    &event_handle,
    EVENT_ALL_ACCESS,
    &attr,
    NotificationEvent,
    FALSE
  );

  // We leak the handle. It's not like we can be loaded twice, and if we die the session is dead anyways
}

#define GET_ORIGINAL_FUNC(name) (*get_original_from_hook_address_wrapper(&name ## _Hook))

static VOID NTAPI DllLoadCallback(PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);

static RTL_VERIFIER_DLL_DESCRIPTOR s_dll_descriptors[] = { {} };

static RTL_VERIFIER_PROVIDER_DESCRIPTOR s_provider_descriptor =
{
  sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR),
  s_dll_descriptors,
  &DllLoadCallback
};

BOOL WINAPI DllMain(
  PVOID dll_handle,
  DWORD reason,
  PRTL_VERIFIER_PROVIDER_DESCRIPTOR* provider
)
{
  switch (reason)
  {
  case DLL_PROCESS_ATTACH:
    DebugPrint("Attached to process\n");
    LdrDisableThreadCalloutsForDll(dll_handle);
    break;
  case DLL_PROCESS_VERIFIER:
    DebugPrint("Setting verifier provider\n");
    *provider = &s_provider_descriptor;
    break;
  default:
    break;
  }
  return TRUE;
}

static void hook_thunks(PVOID base, PIMAGE_THUNK_DATA thunk, PIMAGE_THUNK_DATA original_thunk)
{
  while (original_thunk->u1.AddressOfData)
  {
    if (!(original_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
    {
      ULONG bitmap = 0u;
      for (const auto& image : s_target_images)
        if (image.base == base)
          bitmap = image.hook_bitmap;

      for (auto i = 0u; i < std::size(s_hooks); ++i)
      {
        if (!(bitmap & (1 << i)))
          continue;

        auto& hook = s_hooks[i];

        const auto by_name = PIMAGE_IMPORT_BY_NAME((char*)base + original_thunk->u1.AddressOfData);
        if ((hook.old_address && hook.old_address == PVOID(thunk->u1.Function)) || 0 == strcmp(by_name->Name, hook.function_name.Buffer))
        {
          hook.old_address = PVOID(thunk->u1.Function);
          DebugPrint("Hooking %s from %p to %p\n", hook.function_name.Buffer, hook.new_address, hook.old_address);
          PVOID target = &thunk->u1.Function;
          SIZE_T target_size = sizeof(PVOID);
          ULONG old_protect;
          auto status = NtProtectVirtualMemory(
            NtCurrentProcess(),
            &target,
            &target_size,
            PAGE_EXECUTE_READWRITE,
            &old_protect
          );
          DebugPrint("First NtProtectVirtualMemory returned with %lX\n", status);
          thunk->u1.Function = ULONG_PTR(hook.new_address);
          status = NtProtectVirtualMemory(
            NtCurrentProcess(),
            &target,
            &target_size,
            old_protect,
            &old_protect
          );
          DebugPrint("Second NtProtectVirtualMemory returned with %lX\n", status);
        }
      }
    }
    thunk++;
    original_thunk++;
  }
}

void apply_iat_hooks_on_dll(PVOID dll)
{
  const auto base = PUCHAR(dll);

  const auto dosh = PIMAGE_DOS_HEADER(dll);
  if (dosh->e_magic != IMAGE_DOS_SIGNATURE)
    return;

  const auto nth = PIMAGE_NT_HEADERS(base + dosh->e_lfanew);
  if (nth->Signature != IMAGE_NT_SIGNATURE)
    return;

  const auto import_dir = &nth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  if (import_dir->VirtualAddress == 0 || import_dir->Size == 0)
    return;

  const auto import_begin = PIMAGE_IMPORT_DESCRIPTOR(base + import_dir->VirtualAddress);
  const auto import_end = PIMAGE_IMPORT_DESCRIPTOR(PUCHAR(import_begin) + import_dir->Size);

  for(auto desc = import_begin; desc < import_end; ++desc)
  {
    if (!desc->Name)
      break;

    const auto thunk = PIMAGE_THUNK_DATA(base + desc->FirstThunk);
    const auto original_thunk = PIMAGE_THUNK_DATA(base + desc->OriginalFirstThunk);

    hook_thunks(base, thunk, original_thunk);
  }
}

void dll_loaded(PVOID base, PCWSTR name)
{
  DebugPrint("Got notification of %S being loaded at %p\n", name, base);

  if (0 == _wcsnicmp(L"winlogon", name, 8))
    signal_loaded();

  for (auto& target : s_target_images)
  {
    if (0 == _wcsnicmp(name, target.name.Buffer, target.name.Length / sizeof(wchar_t)))
    {
      DebugPrint("IAT Hooking %S\n", name);
      target.base = base;
      apply_iat_hooks_on_dll(base);
    }
  }
}

static VOID NTAPI DllLoadCallback(PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved)
{
  UNREFERENCED_PARAMETER(DllSize);
  UNREFERENCED_PARAMETER(Reserved);

  dll_loaded(DllBase, DllName);
}

BOOL
WINAPI
CryptVerifySignatureW_Hook(
  _In_                        HCRYPTHASH  hHash,
  _In_reads_bytes_(dwSigLen)  CONST BYTE  *pbSignature,
  _In_                        DWORD       dwSigLen,
  _In_                        HCRYPTKEY   hPubKey,
  _In_opt_                    LPCWSTR     szDescription,
  _In_                        DWORD       dwFlags
)
{
  UNREFERENCED_PARAMETER(hHash);
  UNREFERENCED_PARAMETER(pbSignature);
  UNREFERENCED_PARAMETER(dwSigLen);
  UNREFERENCED_PARAMETER(hPubKey);
  UNREFERENCED_PARAMETER(szDescription);
  UNREFERENCED_PARAMETER(dwFlags);

  DebugPrint("Called");
  return TRUE;
}

PVOID
WINAPI
ResolveDelayLoadedAPI_Hook(
  _In_       PVOID                             ParentModuleBase,
  _In_       PCIMAGE_DELAYLOAD_DESCRIPTOR      DelayloadDescriptor,
  _In_opt_   PDELAYLOAD_FAILURE_DLL_CALLBACK   FailureDllHook,
  _In_opt_   PDELAYLOAD_FAILURE_SYSTEM_ROUTINE FailureSystemHook,
  _Out_      PIMAGE_THUNK_DATA                 ThunkAddress,
  _Reserved_ ULONG                             Flags
)
{
  const auto ret = GET_ORIGINAL_FUNC(ResolveDelayLoadedAPI)(
    ParentModuleBase,
    DelayloadDescriptor,
    FailureDllHook,
    FailureSystemHook,
    ThunkAddress,
    Flags
  );

  const auto base = (char*)ParentModuleBase;
  
  const auto original_thunk = (PIMAGE_THUNK_DATA)(base + DelayloadDescriptor->ImportNameTableRVA);
  const auto thunk = (PIMAGE_THUNK_DATA)(base + DelayloadDescriptor->ImportAddressTableRVA);

  hook_thunks(base, thunk, original_thunk);

  return ret;
}

BOOL
WINAPI
SetSysColors_Hook(
  _In_                  int             cElements,
  _In_reads_(cElements) CONST INT       *lpaElements,
  _In_reads_(cElements) CONST COLORREF  *lpaRgbValues
)
{
  UNREFERENCED_PARAMETER(cElements);
  UNREFERENCED_PARAMETER(lpaElements);
  UNREFERENCED_PARAMETER(lpaRgbValues);

  DebugPrint("Called");
  return TRUE;
}