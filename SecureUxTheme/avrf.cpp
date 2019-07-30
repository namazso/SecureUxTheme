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

#ifndef _NO_CRT_STDIO_INLINE
#define _NO_CRT_STDIO_INLINE 1
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <ntstatus.h>
#define WIN32_NO_STATUS
#include <windows.h>
#include <winternl.h>
#include <WinCrypt.h>
#include <delayloadhandler.h>

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

typedef PVOID(NTAPI *PDELAYLOAD_FAILURE_SYSTEM_ROUTINE)(
  _In_ PCSTR DllName,
  _In_ PCSTR ProcName
  );

#define RTL_CONSTANT_STRING(s) { \
  sizeof(s) - sizeof((s)[0]), \
  sizeof(s), \
  (std::add_pointer_t<std::remove_const_t<std::remove_pointer_t<std::decay_t<decltype(s)>>>>)(s) \
}

#define NtCurrentProcess() (HANDLE(LONG64(-1)))

EXTERN_C_END

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

struct hook_entry
{
  ANSI_STRING     function_name;
  PVOID           old_address;
  PVOID           new_address;
};

#define DEFINE_HOOK(name) {RTL_CONSTANT_STRING(#name), nullptr, (PVOID)&name ## _Hook}

static hook_entry s_hooks[] =
{
  DEFINE_HOOK(CryptVerifySignatureW),
  DEFINE_HOOK(ResolveDelayLoadedAPI)
};

static UNICODE_STRING const s_target_images[] =
{
  RTL_CONSTANT_STRING(L"themeui"),
  RTL_CONSTANT_STRING(L"themeservice"),
  RTL_CONSTANT_STRING(L"uxinit"),
  RTL_CONSTANT_STRING(L"uxtheme"),
};

template<typename Iter, typename T, typename Pred = std::less<T>>
Iter binary_find(Iter begin, Iter end, const T& val, Pred pred = {})
{
  const auto it = std::lower_bound(begin, end, val, pred);

  return it != end && !pred(val, *it) ? it : end;
}

void* get_original_from_hook_address(void* hook_address)
{
  const hook_entry temp_entry{ {}, nullptr, hook_address };
  const auto it = binary_find(std::begin(s_hooks), std::end(s_hooks), temp_entry,
    [](const hook_entry& a, const hook_entry& b)
  {
    return a.new_address < b.new_address;
  });

  return it->old_address;
}

template <typename T>
T* get_original_from_hook_address_wrapper(T* fn)
{
  return (T*)get_original_from_hook_address((void*)fn);
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
      for (auto& hook : s_hooks)
      {
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

static void apply_iat_hooks_on_dll(PVOID dll)
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

static VOID NTAPI DllLoadCallback(PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved)
{
  UNREFERENCED_PARAMETER(DllSize);
  UNREFERENCED_PARAMETER(Reserved);

  DebugPrint("Got notification of %S being loaded at %p\n", DllName, DllBase);

  for (const auto& target : s_target_images)
  {
    if (0 == _wcsnicmp(DllName, target.Buffer, target.Length / sizeof(wchar_t)))
    {
      DebugPrint("IAT Hooking %S\n", DllName);
      apply_iat_hooks_on_dll(DllBase);
    }
  }
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