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

static BOOL WINAPI CryptImportKey_Hook(
  _In_ HCRYPTPROV hProv,
  _In_reads_bytes_(dwDataLen) CONST BYTE* pbData,
  _In_ DWORD dwDataLen,
  _In_ HCRYPTKEY hPubKey,
  _In_ DWORD dwFlags,
  _Out_ HCRYPTKEY* phKey
);

static decltype(&CryptImportKey_Hook) s_OriginalCryptImportKey;

static PVOID WINAPI ResolveDelayLoadedAPI_Hook(
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
    DEFINE_HOOK(CryptImportKey),        // Main theme signature verification hook
    DEFINE_HOOK(ResolveDelayLoadedAPI), // Hook for delay-loaded APIs to apply IAT hooks
};

static HookTargetImage s_TargetImages[] =
  {
    {RTL_CONSTANT_STRING(L"themeui.dll")},      // CThemeManager2, CThemeManagerShared
    {RTL_CONSTANT_STRING(L"themeservice.dll")}, // Theme service on Windows 8.1
    {RTL_CONSTANT_STRING(L"uxinit.dll")},       // In winlogon, actually loading the styles
    {RTL_CONSTANT_STRING(L"uxtheme.dll")},      // The main theme engine, which is loaded by the above
};

static void HookThunks(PVOID DllBase, PIMAGE_THUNK_DATA Thunk, PIMAGE_THUNK_DATA OriginalThunk) {
  while (OriginalThunk->u1.AddressOfData) {
    if (!(OriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
      for (auto& [FunctionName, OldAddress, NewAddress] : s_Hooks) {
        const auto ByName = (PIMAGE_IMPORT_BY_NAME)((char*)DllBase + OriginalThunk->u1.AddressOfData);
        ANSI_STRING Name{};
        RtlInitAnsiString(&Name, ByName->Name);
        const bool ShouldHook = *OldAddress
                                  ? *OldAddress == (PVOID)Thunk->u1.Function
                                  : RtlEqualString(&Name, &FunctionName, FALSE);
        if (ShouldHook) {
          *OldAddress = (PVOID)Thunk->u1.Function;
          DebugPrint("Hooking %hZ from %p to %p\n", &FunctionName, NewAddress, *OldAddress);
          PVOID Target = &Thunk->u1.Function;
          SIZE_T TargetSize = sizeof(PVOID);
          ULONG OldProtect;
          const auto Status = NtProtectVirtualMemory(
            NtCurrentProcess(),
            &Target,
            &TargetSize,
            PAGE_EXECUTE_READWRITE,
            &OldProtect
          );
          if (NT_SUCCESS(Status)) {
            Thunk->u1.Function = (ULONG_PTR)NewAddress;
            (void)NtProtectVirtualMemory(
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

static void ApplyImportHooksOnDll(PVOID DllBase) {
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

void WinlogonChores();

void DllLoadNotification(PVOID DllBase, PUNICODE_STRING DllBaseName) {
  DebugPrint("Got notification of %wZ being loaded at %p\n", DllBaseName, DllBase);

  UNICODE_STRING WinLogon = RTL_CONSTANT_STRING(L"winlogon");
  if (RtlPrefixUnicodeString(&WinLogon, DllBaseName, TRUE))
    WinlogonChores();

  for (auto& TargetImage : s_TargetImages) {
    if (RtlPrefixUnicodeString(&TargetImage.DllBaseName, DllBaseName, TRUE)) {
      DebugPrint("IAT Hooking %wZ\n", DllBaseName);
      TargetImage.DllBase = DllBase;
      ApplyImportHooksOnDll(DllBase);
    }
  }
}

static PVOID WINAPI ResolveDelayLoadedAPI_Hook(
  _In_ PVOID ParentModuleBase,
  _In_ PCIMAGE_DELAYLOAD_DESCRIPTOR DelayloadDescriptor,
  _In_opt_ PDELAYLOAD_FAILURE_DLL_CALLBACK FailureDllHook,
  _In_opt_ PDELAYLOAD_FAILURE_SYSTEM_ROUTINE FailureSystemHook,
  _Out_ PIMAGE_THUNK_DATA ThunkAddress,
  _Reserved_ ULONG Flags
) {
  // This function is called by the delay loader to resolve a delay-loaded API. It is used to hook the delay-loaded
  // APIs in the target module just like we already do with normal imports.

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
  // if ((s_FixedInFirstHook = FAILED(ret))
  //   ret = S_OK;
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
  // if (!s_FixedInFirstHook && FAILED(ret))
  //   ret = S_OK;
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

/// Hook return address FramesToSkip frames above the given context, or the current one if none given.
///
/// This function walks up the given number of frames, then replaces the return address of the last frame.
///
/// @param FramesToSkip The number of frames to skip, starting from the current frame.
/// @param RetHook The hook to set as the return address.
/// @param RetOriginal Pointer to the original return address. This will be set to the original return
///                    address if it was not already set. If it was, the current return address will
///                    be checked against it.
/// @param Context Context to start from, in case you want to ReturnHook from somewhere deeper.
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

#else

static bool WasCreateKeyInlined(void* Function) {
  // This is a hack to detect if CreateKey was inlined by looking for E_FAIL which only Verify can return

#if defined(_M_X64)

  // On x64 we can just look for the E_FAIL signature in the function body, since it is an immediate

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

  // On ARM64 immediates are stashed after the function, aligned. Also, RUNTIME_FUNCTION has no EndAddress. So here we
  // just get the BeginAddress of the next function (remember, RUNTIME_FUNCTIONs are sorted) and scan until that.

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

/// Return, but across multiple frames.
///
/// This function unwinds the given number of frames, then sets the return value provided, emulating as if this number
/// of functions returned, with the last one returning the value provided in RetVal. Can be used to hook a callee when
/// you don't have a convenient way to hook it directly and actually just want to stub it out with a return value.
///
/// @param FramesToSkip The number of frames to skip, starting from the current frame.
/// @param RetVal The value to return from the last frame.
/// @param Context Context to start from, in case you want to SuperReturn from somewhere deeper.
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

    if (const auto FunctionEntry = RtlLookupFunctionEntry(ControlPc, &ImageBase, nullptr)) {
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
        nullptr
      );
    } else {
      // leaf
      CTX_IP(Context) = *(ULONG64*)CTX_SP(Context);
      CTX_SP(Context) += sizeof(ULONG64);
    }

    ControlPc = CTX_IP(Context);
  }

  CTX_RV(Context) = RetVal;

#undef CTX_IP
#undef CTX_SP
#undef CTX_RV

  (void)NtContinue(Context, FALSE);
}

#endif

static BOOL WINAPI CryptImportKey_Hook(
  _In_ HCRYPTPROV hProv,
  _In_reads_bytes_(dwDataLen) CONST BYTE* pbData,
  _In_ DWORD dwDataLen,
  _In_ HCRYPTKEY hPubKey,
  _In_ DWORD dwFlags,
  _Out_ HCRYPTKEY* phKey
) {
  // This is the main theme signature verification disabling hook. To fully understand how it operates, we need to
  // first understand how the verification works in the first place. We're mainly concerned with two functions, which
  // I provide here in reverse-engineered form:
  //
  // HRESULT CThemeSignature::CreateKey()
  // {
  //   HRESULT hr;
  //   DWORD LastError;
  //
  //   hr = 0;
  //   if (!CryptImportKey(this->_hCryptProvider, this->_pvSignature, this->_dwSignatureSize, 0, 0, &this->_hCryptKey)) {
  //     LastError = GetLastError();
  //     return this->_FixCryptoError(LastError);
  //   }
  //   return hr;
  // }
  //
  // HRESULT CThemeSignature::Verify(HANDLE File) {
  //   HRESULT hr;
  //   DWORD LastError;
  //   BYTE pbSignature[128];
  //
  //   if (!this->_hCryptProvider || !this->_hCryptHash)
  //     return E_FAIL;
  //   hr = this->CreateKey();
  //   if (SUCCEEDED(hr)) {
  //     hr = this->CalculateHash(File);
  //     if (SUCCEEDED(hr)) {
  //       memset(pbSignature, 0, sizeof(pbSignature));
  //       hr = this->ReadSignature(File, pbSignature);
  //       if (SUCCEEDED(hr)) {
  //         if (CryptVerifySignatureW(
  //               this->_hCryptHash,
  //               pbSignature,
  //               sizeof(pbSignature),
  //               this->_hCryptKey,
  //               L"Microsoft Visual Style Signature",
  //               0
  //             )) {
  //           return 0;
  //         } else {
  //           LastError = GetLastError();
  //           return this->_FixCryptoError(LastError);
  //         }
  //       }
  //     }
  //   }
  //   return hr;
  // }
  //
  // Originally, SecureUxTheme hooked CryptVerifySignatureW so that invalid signatures would also pass. However,
  // this meant that there needed to be a signature present in the first place, which is usually not the case.
  //
  // Since version 4, SecureUxTheme hooks CryptImportKey instead, which is called by CreateKey, which is in turn
  // called by Verify. As an ordinary hook this is not ideal, since there's no "proper" context we control that
  // could possibly make ReadSignature not fail on the missing signature, and the only way to avoid that function
  // is to return a failure from CreateKey, which would then cause Verify to fail as well. Instead, we choose to
  // mess with the stack contents to alter control flow in a way we can fix up the return value from Verify.
  //
  // On x86, we do this by replacing the return address of Verify with a hook that checks the return value and
  // replaces it with success if it originally was a failure. Unfortunately, we aren't sure if CreateKey was
  // inlined into Verify, so we hook both two and three frames above the current function. If the first hook is
  // successful, we skip tampering with the return value in the second hook, since we don't know what it hooked.
  // This seems to work well enough on the tested Windows versions, and even if it doesn't, the worst that can
  // happen is that the signature verification fails on unsigned themes. Still better than a crash.
  //
  // On x64 and ARM64, we have a harder task: we can't just replace the return address because CET/PAC will stop
  // us from doing that. Instead, we unwind the stack to the point where Verify was called, and set the return
  // value to S_OK, which is what it normally returns on success. The only complication is that we don't know if
  // CreateKey was inlined into Verify, so we need to guess if our caller "looks like" Verify. We do this by
  // checking if the function contains the E_FAIL constant, which is only returned by Verify, and not CreateKey.
  //
  // This approach was confirmed working on the following Windows versions:
  //
  // - Windows 8.1 x64 (9600)
  // - Windows 10 1809 x64 (17763)
  // - Windows 10 21H2 x86 (19044)
  // - Windows 10 21H2 x64 (19044)
  // - Windows 10 22H2 x64 (19045)
  // - Windows Server 2022 x64 (20348)
  // - Windows 11 24H2 x64 (26100)
  // - Windows 11 24H2 ARM64 (26100)

#if defined(_M_IX86)
  ReturnHookX86(2, &RetHook1, &s_OriginalRetAddr1, nullptr);
  ReturnHookX86(3, &RetHook2, &s_OriginalRetAddr2, nullptr);

  return s_OriginalCryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);

#else

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

#endif
}
