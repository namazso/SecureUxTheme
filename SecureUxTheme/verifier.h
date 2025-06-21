//  SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
//  Copyright (C) 2025  namazso <admin@namazso.eu>
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

#pragma once

// See AVRF.md to understand how this works

#define DLL_PROCESS_VERIFIER 4

using RTL_VERIFIER_DLL_LOAD_CALLBACK = VOID(NTAPI*)(PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);
using RTL_VERIFIER_DLL_UNLOAD_CALLBACK = VOID(NTAPI*)(PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);
using RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK = VOID(NTAPI*)(PVOID AllocationBase, SIZE_T AllocationSize);

typedef struct _RTL_VERIFIER_THUNK_DESCRIPTOR {
  PCSTR ThunkName;
  PVOID ThunkOldAddress;
  PVOID ThunkNewAddress;
} RTL_VERIFIER_THUNK_DESCRIPTOR, *PRTL_VERIFIER_THUNK_DESCRIPTOR;

typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR {
  PCWSTR DllName;
  DWORD DllFlags;
  PVOID DllAddress;
  PRTL_VERIFIER_THUNK_DESCRIPTOR DllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR, *PRTL_VERIFIER_DLL_DESCRIPTOR;

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR {
  DWORD Length;
  PRTL_VERIFIER_DLL_DESCRIPTOR ProviderDlls;
  RTL_VERIFIER_DLL_LOAD_CALLBACK ProviderDllLoadCallback;
  RTL_VERIFIER_DLL_UNLOAD_CALLBACK ProviderDllUnloadCallback;
  PCWSTR VerifierImage;
  DWORD VerifierFlags;
  DWORD VerifierDebug;
  PVOID RtlpGetStackTraceAddress;
  PVOID RtlpDebugPageHeapCreate;
  PVOID RtlpDebugPageHeapDestroy;
  RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK ProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR, *PRTL_VERIFIER_PROVIDER_DESCRIPTOR;
