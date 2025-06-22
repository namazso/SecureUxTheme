
static void SignalLoaded() {
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

void* Malloc(size_t Size) {
  return RtlAllocateHeap(RtlProcessHeap(), 0, Size);
}

void Free(void* Ptr) {
  RtlFreeHeap(RtlProcessHeap(), 0, Ptr);
}

NTSTATUS AllowWriteForSystem(HANDLE Key) {
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
  SID_IDENTIFIER_AUTHORITY NtAuthority;

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
  if (!SecurityDescriptor)
    return STATUS_NO_MEMORY;

  // Get the current security descriptor
  Status = NtQuerySecurityObject(
    Key,
    DACL_SECURITY_INFORMATION,
    SecurityDescriptor,
    SecurityDescriptorSize,
    &SecurityDescriptorSize
  );

  if (!NT_SUCCESS(Status))
    goto cleanup_security_descriptor;

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
    goto cleanup_security_descriptor;

  // Extract current DACL
  Status = RtlGetDaclSecurityDescriptor(
    SecurityDescriptor,
    &DaclPresent,
    &OldDacl,
    &DaclDefaulted
  );

  if (!NT_SUCCESS(Status))
    goto cleanup_sid;

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
    goto cleanup_sid;
  }

  // Initialize new ACL
  Status = RtlCreateAcl(NewDacl, AclSize, ACL_REVISION);
  if (!NT_SUCCESS(Status))
    goto cleanup_dacl;

  // Add SYSTEM ACE with write access at the beginning
  Status = RtlAddAccessAllowedAce(NewDacl, ACL_REVISION, KEY_SET_VALUE, SystemSid);
  if (!NT_SUCCESS(Status))
    goto cleanup_dacl;

  // Copy existing ACEs from old DACL
  if (OldDacl && OldDacl->AceCount > 0) {
    for (ULONG i = 0; i < OldDacl->AceCount; i++) {
      PVOID Ace;
      Status = RtlGetAce(OldDacl, i, &Ace);
      if (!NT_SUCCESS(Status))
        continue;

      Status = RtlAddAce(NewDacl, ACL_REVISION, MAXDWORD, Ace, ((PACE_HEADER)Ace)->AceSize);
      if (!NT_SUCCESS(Status))
        goto cleanup_dacl;
    }
  }

  // Allocate new security descriptor
  NewSD = (PSECURITY_DESCRIPTOR)(Malloc(SECURITY_DESCRIPTOR_MIN_LENGTH));
  if (!NewSD) {
    Status = STATUS_NO_MEMORY;
    goto cleanup_dacl;
  }

  // Initialize new security descriptor
  Status = RtlCreateSecurityDescriptor(NewSD, SECURITY_DESCRIPTOR_REVISION);
  if (!NT_SUCCESS(Status))
    goto cleanup_sd;

  // Set new DACL in security descriptor
  Status = RtlSetDaclSecurityDescriptor(NewSD, TRUE, NewDacl, FALSE);
  if (!NT_SUCCESS(Status))
    goto cleanup_sd;

  // Apply new security descriptor to the registry key
  Status = NtSetSecurityObject(
    Key,
    DACL_SECURITY_INFORMATION,
    NewSD
  );

cleanup_sd:
  Free(NewSD);
cleanup_dacl:
  Free(NewDacl);
cleanup_sid:
  RtlFreeSid(SystemSid);
cleanup_security_descriptor:
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
    NULL,
    NULL
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
      NtClose(KeyHandle);
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
  ULONG ValueLength = (ULONG)((wcslen(Value) + 1) * sizeof(WCHAR));

  Status = NtSetValueKey(
    KeyHandle,
    ValueNamePtr,
    0,
    REG_EXPAND_SZ,
    (PVOID)Value,
    ValueLength
  );

  // Close the key handle
  NtClose(KeyHandle);

  return Status;
}

static void SetThemeUiProxyKeys() {
  // We can just leave these as ThemeUiProxy.dll is never uninstalled

  RegSetKeyValueExpandString(
    L"\\Registry\\Machine\\SOFTWARE\\Classes\\CLSID\\{9324DA94-50EC-4A14-A770-E90CA03E7C8F}\\InProcServer32",
    L"",
    L"%SystemRoot%\\system32\\ThemeUiProxy.dll"
    );
  RegSetKeyValueExpandString(
    L"\\Registry\\Machine\\SOFTWARE\\Classes\\CLSID\\{c04b329e-5823-4415-9c93-ba44688947b0}\\InProcServer32",
    L"",
    L"%SystemRoot%\\system32\\ThemeUiProxy.dll"
    );
  if constexpr (sizeof(void*) == 8) {
    RegSetKeyValueExpandString(
      L"\\Registry\\Machine\\SOFTWARE\\Classes\\Wow6432Node\\CLSID\\{9324DA94-50EC-4A14-A770-E90CA03E7C8F}\\InProcServer32",
      L"",
      L"%SystemRoot%\\system32\\ThemeUiProxy.dll"
    );
    RegSetKeyValueExpandString(
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
  auto Status = NtOpenKey(&Handle, KEY_SET_VALUE, &Attributes);
  if (Status == STATUS_OBJECT_NAME_NOT_FOUND || Status == STATUS_OBJECT_PATH_NOT_FOUND)
    return STATUS_SUCCESS;

  if (!NT_SUCCESS(Status))
    return Status;

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
    L"WindowText"
  };

  for (auto Color : Colors) {
    UNICODE_STRING value{};
    RtlInitUnicodeString(&value, Color);
    NtDeleteValueKey(Handle, &value);
  }

  NtClose(Handle);

  return STATUS_SUCCESS;
}

void WinlogonChores() {
  SignalLoaded();
  SetThemeUiProxyKeys();
  auto Status = DeleteDefaultColors(false);
  if (!NT_SUCCESS(Status)) {
    DebugPrint("Failed to delete standard default colors: %lX\n", Status);
  }
  Status = DeleteDefaultColors(true);
  if (!NT_SUCCESS(Status)) {
    DebugPrint("Failed to delete high contrast default colors: %lX\n", Status);
  }
}