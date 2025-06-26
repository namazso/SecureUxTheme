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

static void SignalLoaded() {
  ULONG SessionId{};
  {
    ULONG ReturnLength{};
    const auto Status = NtQueryInformationToken(
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
  (void)NtCreateEvent(
    &Handle,
    EVENT_ALL_ACCESS,
    &Attributes,
    NotificationEvent,
    FALSE
  );

  // We leak the handle. It's not like we can be loaded twice, and if we die, the session is dead anyway
}

static void* Malloc(size_t Size) {
  return RtlAllocateHeap(RtlProcessHeap(), 0, Size);
}

static void Free(void* Ptr) {
  RtlFreeHeap(RtlProcessHeap(), 0, Ptr);
}

static NTSTATUS AllowWriteForSystem(HANDLE Key) {
  NTSTATUS Status = STATUS_SUCCESS;
  ULONG SecurityDescriptorSize = 0;
  PSECURITY_DESCRIPTOR SecurityDescriptor = nullptr;
  PSID SystemSid = nullptr;
  PACL NewDacl = nullptr;
  PSECURITY_DESCRIPTOR NewSD = nullptr;
  BOOLEAN DaclPresent;
  BOOLEAN DaclDefaulted;
  PACL OldDacl = nullptr;
  ULONG AclSize = 0;
  SID_IDENTIFIER_AUTHORITY NtAuthority = {};

  // Get the required security descriptor size
  Status = NtQuerySecurityObject(
    Key,
    DACL_SECURITY_INFORMATION,
    nullptr,
    0,
    &SecurityDescriptorSize
  );

  if (Status != STATUS_BUFFER_TOO_SMALL)
    return Status;

  // Allocate security descriptor
  SecurityDescriptor = (PSECURITY_DESCRIPTOR)(Malloc(SecurityDescriptorSize));
  if (!SecurityDescriptor) {
    Status = STATUS_NO_MEMORY;
    goto Cleanup;
  }

  // Get the current security descriptor
  Status = NtQuerySecurityObject(
    Key,
    DACL_SECURITY_INFORMATION,
    SecurityDescriptor,
    SecurityDescriptorSize,
    &SecurityDescriptorSize
  );

  if (!NT_SUCCESS(Status))
    goto Cleanup;

  // Get the SYSTEM SID
  NtAuthority = SECURITY_NT_AUTHORITY;
  Status = RtlAllocateAndInitializeSid(
    &NtAuthority,
    1,
    SECURITY_LOCAL_SYSTEM_RID,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    &SystemSid
  );

  if (!NT_SUCCESS(Status))
    goto Cleanup;

  // Extract current DACL
  Status = RtlGetDaclSecurityDescriptor(
    SecurityDescriptor,
    &DaclPresent,
    &OldDacl,
    &DaclDefaulted
  );

  if (!NT_SUCCESS(Status))
    goto Cleanup;

  // Calculate new ACL size
  AclSize = sizeof(ACL);
  if (OldDacl)
    AclSize = OldDacl->AclSize;

  // Add space for SYSTEM ACE
  AclSize += sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(SystemSid) - sizeof(DWORD);

  // Allocate new DACL
  NewDacl = (PACL)(Malloc(AclSize));
  if (!NewDacl) {
    Status = STATUS_NO_MEMORY;
    goto Cleanup;
  }

  // Initialize new ACL
  Status = RtlCreateAcl(NewDacl, AclSize, ACL_REVISION);
  if (!NT_SUCCESS(Status))
    goto Cleanup;

  // Add SYSTEM ACE with write access at the beginning
  Status = RtlAddAccessAllowedAce(NewDacl, ACL_REVISION, KEY_SET_VALUE, SystemSid);
  if (!NT_SUCCESS(Status))
    goto Cleanup;

  // Copy existing ACEs from old DACL
  if (OldDacl && OldDacl->AceCount > 0) {
    for (ULONG i = 0; i < OldDacl->AceCount; i++) {
      PVOID Ace;
      Status = RtlGetAce(OldDacl, i, &Ace);
      if (!NT_SUCCESS(Status))
        continue;

      Status = RtlAddAce(NewDacl, ACL_REVISION, MAXDWORD, Ace, ((PACE_HEADER)Ace)->AceSize);
      if (!NT_SUCCESS(Status))
        goto Cleanup;
    }
  }

  // Allocate new security descriptor
  NewSD = (PSECURITY_DESCRIPTOR)(Malloc(SECURITY_DESCRIPTOR_MIN_LENGTH));
  if (!NewSD) {
    Status = STATUS_NO_MEMORY;
    goto Cleanup;
  }

  // Initialize new security descriptor
  Status = RtlCreateSecurityDescriptor(NewSD, SECURITY_DESCRIPTOR_REVISION);
  if (!NT_SUCCESS(Status))
    goto Cleanup;

  // Set new DACL in security descriptor
  Status = RtlSetDaclSecurityDescriptor(NewSD, TRUE, NewDacl, FALSE);
  if (!NT_SUCCESS(Status))
    goto Cleanup;

  // Apply new security descriptor to the registry key
  Status = NtSetSecurityObject(
    Key,
    DACL_SECURITY_INFORMATION,
    NewSD
  );

Cleanup:
  if (NewSD)
    Free(NewSD);
  if (NewDacl)
    Free(NewDacl);
  if (SystemSid)
    RtlFreeSid(SystemSid);
  if (SecurityDescriptor)
    Free(SecurityDescriptor);

  return Status;
}

static NTSTATUS RegSetKeyValueExpandString(PCWSTR KeyName, PCWSTR ValueName, PCWSTR Value) {
  UNICODE_STRING KeyNameUnicode;
  RtlInitUnicodeString(&KeyNameUnicode, KeyName);

  OBJECT_ATTRIBUTES KeyAttributes;
  InitializeObjectAttributes(
    &KeyAttributes,
    &KeyNameUnicode,
    OBJ_CASE_INSENSITIVE,
    nullptr,
    nullptr
  );

  // First attempt to open the key
  HANDLE KeyHandle = nullptr;
  NTSTATUS Status = NtOpenKey(
    &KeyHandle,
    KEY_SET_VALUE,
    &KeyAttributes
  );

  // If opening failed, try to adjust permissions and retry
  if (!NT_SUCCESS(Status)) {
    // Try to open with read access first
    Status = NtOpenKey(
      &KeyHandle,
      KEY_READ | WRITE_DAC,
      &KeyAttributes
    );

    if (NT_SUCCESS(Status)) {
      // Got a handle, now adjust permissions
      Status = AllowWriteForSystem(KeyHandle);
      (void)NtClose(KeyHandle);
      KeyHandle = nullptr;

      if (NT_SUCCESS(Status)) {
        // Try opening with write access again
        Status = NtOpenKey(
          &KeyHandle,
          KEY_SET_VALUE,
          &KeyAttributes
        );
      } else {
        DebugPrint("Failed to allow write for SYSTEM on %wZ: %lX", &KeyNameUnicode, Status);
      }
    } else {
      DebugPrint("Failed to open key %wZ for DAC write: %lX", &KeyNameUnicode, Status);
    }

    // If we still couldn't open with write access, return error
    if (!NT_SUCCESS(Status) || !KeyHandle) {
      DebugPrint("Failed to open key %wZ for write: %lX", &KeyNameUnicode, Status);
      return Status;
    }
  }

  PUNICODE_STRING ValueNamePtr = nullptr;
  UNICODE_STRING ValueNameUnicode;
  if (ValueName) {
    ValueNamePtr = &ValueNameUnicode;
    RtlInitUnicodeString(&ValueNameUnicode, ValueName);
  }

  // Calculate string length in bytes (including null terminator)
  const auto ValueLength = (ULONG)((wcslen(Value) + 1) * sizeof(WCHAR));

  Status = NtSetValueKey(
    KeyHandle,
    ValueNamePtr,
    0,
    REG_EXPAND_SZ,
    (PVOID)Value,
    ValueLength
  );

  // Close the key handle
  (void)NtClose(KeyHandle);

  return Status;
}

static void SetThemeUiProxyKeys() {
  // We can just leave these as ThemeUiProxy.dll is never uninstalled

  // IThemeManager2
  (void)RegSetKeyValueExpandString(
    L"\\Registry\\Machine\\SOFTWARE\\Classes\\CLSID\\{9324DA94-50EC-4A14-A770-E90CA03E7C8F}\\InProcServer32",
    L"",
    L"%SystemRoot%\\system32\\ThemeUiProxy.dll"
    );

  // IThemeManagerShared
  (void)RegSetKeyValueExpandString(
    L"\\Registry\\Machine\\SOFTWARE\\Classes\\CLSID\\{c04b329e-5823-4415-9c93-ba44688947b0}\\InProcServer32",
    L"",
    L"%SystemRoot%\\system32\\ThemeUiProxy.dll"
    );
  if constexpr (sizeof(void*) == 8) {
    // On 64-bit systems, we also need to set the Wow6432Node keys for 32-bit processes, in case someone wants to
    // set a theme from a 32-bit process.

    (void)RegSetKeyValueExpandString(
      L"\\Registry\\Machine\\SOFTWARE\\Classes\\Wow6432Node\\CLSID\\{9324DA94-50EC-4A14-A770-E90CA03E7C8F}\\InProcServer32",
      L"",
      L"%SystemRoot%\\system32\\ThemeUiProxy.dll"
    );
    (void)RegSetKeyValueExpandString(
      L"\\Registry\\Machine\\SOFTWARE\\Classes\\Wow6432Node\\CLSID\\{c04b329e-5823-4415-9c93-ba44688947b0}\\InProcServer32",
      L"",
      L"%SystemRoot%\\system32\\ThemeUiProxy.dll"
    );
  }
}

static NTSTATUS DeleteDefaultColors(bool HighContrast) {
  UNICODE_STRING Name{};
  OBJECT_ATTRIBUTES Attributes{};

  constexpr static auto STANDARD = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\DefaultColors\\Standard";
  constexpr static auto HIGH_CONTRAST = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\DefaultColors\\HighContrast";

  RtlInitUnicodeString(&Name, HighContrast ? HIGH_CONTRAST : STANDARD);
  InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

  HANDLE Handle{};
  const auto Status = NtOpenKey(&Handle, KEY_SET_VALUE, &Attributes);
  if (Status == STATUS_OBJECT_NAME_NOT_FOUND || Status == STATUS_OBJECT_PATH_NOT_FOUND)
    return STATUS_SUCCESS;

  if (!NT_SUCCESS(Status))
    return Status;

  // List from LogonController.dll
  static constexpr const wchar_t* Colors[] = {
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
    L"WindowText",
  };

  for (const auto Color : Colors) {
    UNICODE_STRING value{};
    RtlInitUnicodeString(&value, Color);
    (void)NtDeleteValueKey(Handle, &value);
  }

  (void)NtClose(Handle);

  return STATUS_SUCCESS;
}

void WinlogonChores() {

  // Various chores that we can't do in the installer, and as such are done here, when the DLL is loaded by winlogon.

  static bool s_AlreadyDone = false;
  if (s_AlreadyDone)
    return;
  s_AlreadyDone = true;

  // Create an event named "SecureUxTheme_Loaded" in the current session.
  SignalLoaded();

  // Hijack IThemeManager2 and IThemeManagerShared CLSIDs with our own proxy dll.
  SetThemeUiProxyKeys();

  // Delete the default colors from the registry. LogonUI always resets colors to these, but they are only updated
  // when the theme you're switching to is a high contrast theme. It's better to just make it not set anything.
  auto Status = DeleteDefaultColors(false);
  if (!NT_SUCCESS(Status)) {
    DebugPrint("Failed to delete standard default colors: %lX\n", Status);
  }

  // Also delete the high contrast versions, in case one of the users has a high contrast theme set.
  Status = DeleteDefaultColors(true);
  if (!NT_SUCCESS(Status)) {
    DebugPrint("Failed to delete high contrast default colors: %lX\n", Status);
  }
}