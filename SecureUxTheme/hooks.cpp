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

BOOL WINAPI CryptImportKey_Hook(
  _In_ HCRYPTPROV hProv,
  _In_reads_bytes_(dwDataLen) CONST BYTE* pbData,
  _In_ DWORD dwDataLen,
  _In_ HCRYPTKEY hPubKey,
  _In_ DWORD dwFlags,
  _Out_ HCRYPTKEY* phKey
);

static decltype(&CryptImportKey_Hook) s_OriginalCryptImportKey;

PVOID WINAPI ResolveDelayLoadedAPI_Hook(
  _In_ PVOID ParentModuleBase,
  _In_ PCIMAGE_DELAYLOAD_DESCRIPTOR DelayloadDescriptor,
  _In_opt_ PDELAYLOAD_FAILURE_DLL_CALLBACK FailureDllHook,
  _In_opt_ PDELAYLOAD_FAILURE_SYSTEM_ROUTINE FailureSystemHook,
  _Out_ PIMAGE_THUNK_DATA ThunkAddress,
  _Reserved_ ULONG Flags
);

static decltype(&ResolveDelayLoadedAPI_Hook) s_OriginalResolveDelayLoadedAPI;

struct HookEntry {
  ANSI_STRING FunctionName;
  PVOID* OldAddress;
  PVOID NewAddress;
};

struct HookTargetImage {
  UNICODE_STRING DllBaseName{};
  PVOID DllBase{};
};

#define DEFINE_HOOK(name) \
  {RTL_CONSTANT_STRING(#name), (PVOID*)&s_Original##name, (PVOID) & name##_Hook}

static HookEntry s_Hooks[] =
  {
    DEFINE_HOOK(CryptImportKey),
    DEFINE_HOOK(ResolveDelayLoadedAPI),
};

static HookTargetImage s_TargetImages[] =
  {
    {RTL_CONSTANT_STRING(L"themeui.dll")},
    {RTL_CONSTANT_STRING(L"themeservice.dll")},
    {RTL_CONSTANT_STRING(L"uxinit.dll")},
    {RTL_CONSTANT_STRING(L"uxtheme.dll")},
};

static void HookThunks(PVOID DllBase, PIMAGE_THUNK_DATA Thunk, PIMAGE_THUNK_DATA OriginalThunk) {
  while (OriginalThunk->u1.AddressOfData) {
    if (!(OriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
      for (auto& Hook : s_Hooks) {
        const auto ByName = (PIMAGE_IMPORT_BY_NAME)((char*)DllBase + OriginalThunk->u1.AddressOfData);
        ANSI_STRING FunctionName{};
        RtlInitAnsiString(&FunctionName, ByName->Name);
        bool ShouldHook = *Hook.OldAddress
                            ? *Hook.OldAddress == (PVOID)Thunk->u1.Function
                            : RtlEqualString(&FunctionName, &Hook.FunctionName, FALSE);
        if (ShouldHook) {
          *Hook.OldAddress = (PVOID)Thunk->u1.Function;
          DebugPrint("Hooking %hZ from %p to %p\n", &Hook.FunctionName, Hook.NewAddress, *Hook.OldAddress);
          PVOID Target = &Thunk->u1.Function;
          SIZE_T TargetSize = sizeof(PVOID);
          ULONG OldProtect;
          auto Status = NtProtectVirtualMemory(
            NtCurrentProcess(),
            &Target,
            &TargetSize,
            PAGE_EXECUTE_READWRITE,
            &OldProtect
          );
          if (NT_SUCCESS(Status)) {
            Thunk->u1.Function = (ULONG_PTR)Hook.NewAddress;
            NtProtectVirtualMemory(
              NtCurrentProcess(),
              &Target,
              &TargetSize,
              OldProtect,
              &OldProtect
            );
          } else {
            DebugPrint("NtProtectVirtualMemory failed with %lX\n", Status);
          }
        }
      }
    }
    Thunk++;
    OriginalThunk++;
  }
}

void ApplyImportHooksOnDll(PVOID DllBase) {
  const auto Base = (PUCHAR)DllBase;

  const auto DosHeader = (PIMAGE_DOS_HEADER)DllBase;
  if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    return;

  const auto NtHeaders = (PIMAGE_NT_HEADERS)(Base + DosHeader->e_lfanew);
  if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    return;

  const auto ImportDirectory = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  if (ImportDirectory->VirtualAddress == 0 || ImportDirectory->Size == 0)
    return;

  const auto ImportBegin = (PIMAGE_IMPORT_DESCRIPTOR)(Base + ImportDirectory->VirtualAddress);
  const auto ImportEnd = (PIMAGE_IMPORT_DESCRIPTOR)((PUCHAR)(ImportBegin) + ImportDirectory->Size);

  for (auto it = ImportBegin; it < ImportEnd; ++it) {
    if (!it->Name)
      break;

    const auto Thunk = (PIMAGE_THUNK_DATA)(Base + it->FirstThunk);
    const auto OriginalThunk = (PIMAGE_THUNK_DATA)(Base + it->OriginalFirstThunk);

    HookThunks(Base, Thunk, OriginalThunk);
  }
}

void SignalLoaded() {
  ULONG SessionId{};
  {
    ULONG ReturnLength{};
    auto Status = NtQueryInformationToken(
      NtCurrentProcessToken(),
      TokenSessionId,
      &SessionId,
      sizeof(SessionId),
      &ReturnLength
    );
    if (!NT_SUCCESS(Status))
      return;
  }

  wchar_t FullName[128];
  swprintf_s(FullName, L"\\Sessions\\%lu\\BaseNamedObjects\\SecureUxTheme_Loaded", SessionId);

  UNICODE_STRING NameStr;
  RtlInitUnicodeString(&NameStr, FullName);

  OBJECT_ATTRIBUTES Attributes;
  InitializeObjectAttributes(
    &Attributes,
    &NameStr,
    0,
    nullptr,
    nullptr
  );
  HANDLE Handle = nullptr;
  NtCreateEvent(
    &Handle,
    EVENT_ALL_ACCESS,
    &Attributes,
    NotificationEvent,
    FALSE
  );

  // We leak the handle. It's not like we can be loaded twice, and if we die, the session is dead anyway
}

void DllLoadNotification(PVOID DllBase, PUNICODE_STRING DllBaseName) {
  DebugPrint("Got notification of %wZ being loaded at %p\n", DllBaseName, DllBase);

  UNICODE_STRING WinLogon = RTL_CONSTANT_STRING(L"winlogon");
  if (RtlPrefixUnicodeString(&WinLogon, DllBaseName, TRUE))
    SignalLoaded();

  for (auto& TargetImage : s_TargetImages) {
    if (RtlPrefixUnicodeString(&TargetImage.DllBaseName, DllBaseName, TRUE)) {
      DebugPrint("IAT Hooking %wZ\n", DllBaseName);
      TargetImage.DllBase = DllBase;
      ApplyImportHooksOnDll(DllBase);
    }
  }
}

PVOID WINAPI ResolveDelayLoadedAPI_Hook(
  _In_ PVOID ParentModuleBase,
  _In_ PCIMAGE_DELAYLOAD_DESCRIPTOR DelayloadDescriptor,
  _In_opt_ PDELAYLOAD_FAILURE_DLL_CALLBACK FailureDllHook,
  _In_opt_ PDELAYLOAD_FAILURE_SYSTEM_ROUTINE FailureSystemHook,
  _Out_ PIMAGE_THUNK_DATA ThunkAddress,
  _Reserved_ ULONG Flags
) {
  const auto RetVal = s_OriginalResolveDelayLoadedAPI(
    ParentModuleBase,
    DelayloadDescriptor,
    FailureDllHook,
    FailureSystemHook,
    ThunkAddress,
    Flags
  );

  const auto DllBase = (char*)ParentModuleBase;

  const auto OriginalThunk = (PIMAGE_THUNK_DATA)(DllBase + DelayloadDescriptor->ImportNameTableRVA);
  const auto Thunk = (PIMAGE_THUNK_DATA)(DllBase + DelayloadDescriptor->ImportAddressTableRVA);

  HookThunks(DllBase, Thunk, OriginalThunk);

  return RetVal;
}

#if defined(_M_IX86)

static bool s_FixedInFirstHook = false;

static PVOID s_OriginalRetAddr1 = nullptr;

static __declspec(naked) void RetHook1() {
  __asm {
    test eax, eax
    sets byte ptr [s_FixedInFirstHook]
    jns NoMatch
    xor eax, eax
  NoMatch:
    jmp [s_OriginalRetAddr1]
  }
}

static PVOID s_OriginalRetAddr2 = nullptr;

static __declspec(naked) void RetHook2() {
  __asm {
    test [s_FixedInFirstHook], 1
    jnz AlreadyFixed
    test eax, eax
    jns AlreadyFixed
    xor eax, eax
  AlreadyFixed:
    jmp [s_OriginalRetAddr2]
  }
}

static DECLSPEC_NOINLINE void ReturnHookX86(
  _In_ ULONG FramesToSkip,
  _In_ void (*RetHook)(),
  _In_ PVOID* RetOriginal,
  _In_opt_ PCONTEXT Context
) {
  CONTEXT LocalContext;
  if (!Context) {
    LocalContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    RtlCaptureContext(&LocalContext);
    Context = &LocalContext;
  }

  auto CurrentEbp = (PULONG_PTR)Context->Ebp;
  auto CurrentEipPtr = (PULONG_PTR)(Context->Esp + sizeof(ULONG_PTR));

  for (ULONG i = 0; i < FramesToSkip; i++) {
    CurrentEipPtr = &CurrentEbp[1];
    CurrentEbp = (PULONG_PTR)CurrentEbp[0];
  }

  if (!*RetOriginal || *RetOriginal == (PVOID)*CurrentEipPtr) {
    *RetOriginal = (PVOID)*CurrentEipPtr;
    *CurrentEipPtr = (ULONG_PTR)(PVOID)RetHook;
  }
}

BOOL WINAPI CryptImportKey_Hook(
  _In_ HCRYPTPROV hProv,
  _In_reads_bytes_(dwDataLen) CONST BYTE* pbData,
  _In_ DWORD dwDataLen,
  _In_ HCRYPTKEY hPubKey,
  _In_ DWORD dwFlags,
  _Out_ HCRYPTKEY* phKey
) {
  ReturnHookX86(2, &RetHook1, &s_OriginalRetAddr1, nullptr);
  ReturnHookX86(3, &RetHook2, &s_OriginalRetAddr2, nullptr);

  return s_OriginalCryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
}

#else

static bool WasCreateKeyInlined(void* Function) {
  // This is a hack to detect if CreateKey was inlined by looking for E_FAIL which only Verify can return

#if defined(_M_X64)

  ULONG64 ImageBase;
  const auto Entry = RtlLookupFunctionEntry((ULONG64)Function, &ImageBase, nullptr);

  const auto Begin = (PUCHAR)ImageBase + Entry->BeginAddress;
  const auto End = (PUCHAR)ImageBase + Entry->EndAddress;
  for (auto it = Begin; it < End; ++it) {
    // E_FAIL
    if (0 == memcmp(it, "\x05\x40\x00\x80", 4)) {
      return true;
    }
  }

  return false;

#elif defined(_M_ARM64)

  ULONG64 ImageBase;
  const auto Entry = RtlLookupFunctionEntry((ULONG64)Function, &ImageBase, nullptr);

  const auto Begin = (PULONG)((PUCHAR)ImageBase + Entry->BeginAddress);
  const auto End = (PULONG)((PUCHAR)ImageBase + (Entry + 1)->BeginAddress);
  for (auto it = Begin; it < End; ++it) {
    if (E_FAIL == *it) {
      return true;
    }
  }

  return false;

#else
#error Unsupported architecture!
#endif
}

// Return, but across multiple frames.
//
// This function unwinds the given number of frames, then sets the return value provided, emulating as if this number
// of functions returned, with the last one returning the value provided in RetVal. Can be used to hook a callee when
// you don't have a convenient way to hook it directly and actually just want to stub it out with a return value.
//
// @param FramesToSkip The number of frames to skip, starting from the current frame.
// @param RetVal The value to return from the last frame.
// @param Context Context to start from, in case you want to SuperReturn from somewhere deeper.
static DECLSPEC_NOINLINE void SuperReturn(
  _In_ ULONG FramesToSkip,
  _In_opt_ ULONG_PTR RetVal,
  _In_opt_ PCONTEXT Context
) {
  CONTEXT LocalContext;
  if (!Context) {
    FramesToSkip += 1; // skip this frame
    LocalContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    RtlCaptureContext(&LocalContext);
    Context = &LocalContext;
  }

#if defined(_M_X64)
#define CTX_IP(Ctx) (Ctx->Rip)
#define CTX_SP(Ctx) (Ctx->Rsp)
#define CTX_RV(Ctx) (Ctx->Rax)
#elif defined(_M_ARM64)
#define CTX_IP(Ctx) (Ctx->Pc)
#define CTX_SP(Ctx) (Ctx->Sp)
#define CTX_RV(Ctx) (Ctx->X0)
#elif defined(_M_IX86)
#error Can't possibly work on x86: no way to restore nonvolatile registers.
#else
#error Unsupported architecture!
#endif

  ULONG64 ControlPc = CTX_IP(Context);

  for (ULONG i = 0; i < FramesToSkip; i++) {
    ULONG_PTR ImageBase = 0;
    PRUNTIME_FUNCTION FunctionEntry = RtlLookupFunctionEntry(ControlPc, &ImageBase, NULL);

    if (!FunctionEntry) {
      // leaf
      CTX_IP(Context) = *(ULONG64*)CTX_SP(Context);
      CTX_SP(Context) += sizeof(ULONG64);
    } else {
      PVOID HandlerData;
      ULONG64 EstablisherFrame;
      RtlVirtualUnwind(
        UNW_FLAG_NHANDLER,
        ImageBase,
        ControlPc,
        FunctionEntry,
        Context,
        &HandlerData,
        &EstablisherFrame,
        NULL
      );
    }

    ControlPc = CTX_IP(Context);
  }

  CTX_RV(Context) = RetVal;

#undef CTX_IP
#undef CTX_SP
#undef CTX_RV

  NtContinue(Context, FALSE);
}

BOOL WINAPI CryptImportKey_Hook(
  _In_ HCRYPTPROV hProv,
  _In_reads_bytes_(dwDataLen) CONST BYTE* pbData,
  _In_ DWORD dwDataLen,
  _In_ HCRYPTKEY hPubKey,
  _In_ DWORD dwFlags,
  _Out_ HCRYPTKEY* phKey
) {
  UNREFERENCED_PARAMETER(hProv);
  UNREFERENCED_PARAMETER(pbData);
  UNREFERENCED_PARAMETER(dwDataLen);
  UNREFERENCED_PARAMETER(hPubKey);
  UNREFERENCED_PARAMETER(dwFlags);
  UNREFERENCED_PARAMETER(phKey);

  const auto RetAddr = _ReturnAddress();

  const auto SkipFrames = WasCreateKeyInlined(RetAddr) ? 2 : 3;

  SuperReturn(SkipFrames, 0, nullptr);

  return 0; // Never actually reached
}

#endif
