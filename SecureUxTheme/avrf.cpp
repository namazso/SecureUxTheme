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

static VOID NTAPI DllLoadCallback(PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);

static RTL_VERIFIER_DLL_DESCRIPTOR s_DllDescriptors[] = {{}};

static RTL_VERIFIER_PROVIDER_DESCRIPTOR s_ProviderDescriptor =
  {
    sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR),
    s_DllDescriptors,
    &DllLoadCallback
};

void DllLoadNotification(PVOID DllBase, PUNICODE_STRING DllName);

static VOID NTAPI DllLoadCallback(PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved) {
  UNREFERENCED_PARAMETER(DllSize);
  UNREFERENCED_PARAMETER(Reserved);

  UNICODE_STRING DllNameStr{};
  RtlInitUnicodeString(&DllNameStr, DllName);
  DllLoadNotification(DllBase, &DllNameStr);
}

static VOID NTAPI DllNotification(
  _In_ ULONG NotificationReason,
  _In_ PLDR_DLL_NOTIFICATION_DATA NotificationData,
  _In_opt_ PVOID Context
) {
  UNREFERENCED_PARAMETER(Context);

  if (NotificationReason != LDR_DLL_NOTIFICATION_REASON_LOADED)
    return;

  const auto& Loaded = NotificationData->Loaded;

  DllLoadNotification(Loaded.DllBase, Loaded.BaseDllName);
}

static VOID NTAPI EnumProc(
  _In_ PLDR_DATA_TABLE_ENTRY ModuleInformation,
  _In_ PVOID Parameter,
  _Out_ BOOLEAN* Stop
) {
  UNREFERENCED_PARAMETER(Parameter);
  DllLoadNotification(ModuleInformation->DllBase, &ModuleInformation->BaseDllName);
  *Stop = FALSE;
}

BOOL WINAPI DllMain(
  PVOID DllHandle,
  DWORD Reason,
  PRTL_VERIFIER_PROVIDER_DESCRIPTOR* Provider
) {
  switch (Reason) {
  case DLL_PROCESS_ATTACH: {
    PVOID Cookie{};
    DebugPrint("Attached to process\n");
    (void)LdrDisableThreadCalloutsForDll(DllHandle);
    decltype(&LdrRegisterDllNotification) FnLdrRegisterDllNotification = nullptr;

    // For some reason, this isn't in implibs
    {
      PVOID NtdllBase = nullptr;
      RtlPcToFileHeader(&RtlPcToFileHeader, &NtdllBase);
      ANSI_STRING Str = RTL_CONSTANT_STRING("LdrRegisterDllNotification");
      (void)LdrGetProcedureAddress(NtdllBase, &Str, 0, (PVOID*)&FnLdrRegisterDllNotification);
    }

    (void)FnLdrRegisterDllNotification(0, DllNotification, nullptr, &Cookie);
    (void)LdrEnumerateLoadedModules(FALSE, &EnumProc, nullptr);
    DebugPrint("Enumerated already loaded modules\n");
    break;
  }
  case DLL_PROCESS_VERIFIER:
    DebugPrint("Setting verifier provider\n");
    *Provider = &s_ProviderDescriptor;
    break;
  default:
    break;
  }
  return TRUE;
}
