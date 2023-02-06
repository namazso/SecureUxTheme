# Application Verifier Custom Providers

This post isn't innovation or anything. It is a renewing of an old microsoft blogpost (and some other publication vanished in time and dated back to 2004(?)). Recently, I have been looking over this method to solve a very specific task, unfortunately it didn't help me, but I thought it will be interesting to share this (again) with everybody.

Expected target system is x64, however it will be the same for x86.

## Information

**What is Application Verifier (AVrf)?**

It is a built-in Windows Native debugging mechanism. It is supported everywhere in all actual NT versions (and in Windows XP too).

You can read about it here -> [MSDN: Application Verifier](http://msdn.microsoft.com/en-us/library/ms220948(v=vs.90).aspx)

And also in the WinDBG documentation -> [!avrf WinDBG command](http://msdn.microsoft.com/en-us/library/Windows/hardware/ff562138(v=vs.85).aspx)

**What are the requirements to use it?**

Administrator rights required, for write access for the IFEO registry key (Image File Execution Options) and the %SystemRoot%\System32 directory.

**How does it work?**

It is a DLL injection based debugging mechanism built on IAT hooking. Windows will give you a free, stable and easy to use hooking mechanism in addition to dll injection at the earlier stage of process loading.

You have to create a dll, which is called a "Custom Verifier Provider DLL", by writing a dllmain.cpp file, declaring the InitRoutine entrypoint, and registering the dll as a "verifier provider" by checking if the fdwReason parameter is set to `DLL_PROCESS_VERIFIER`, and if so, call `RegisterProvider()`. After that you can add your code. (full example provided). Keep in mind, the InitRoutine entrypoint is the same as the DllMain entrypoint

Your code will be loaded just after verifier at earlier process startup time when no other dlls are loaded except ntdll, api set schema and verifier dlls. Note that because nothing else loaded at time when your code gets control you should be using Native API at entry code. Later usual dlls will be loaded (depends on appplication imports of course).

## AVrf Declarations and Structures

Some of these can be found in old DDK files, but keep in mind, this stuff isn't documented and may change in the next version of Windows. However, it didn't change since XP and works perfectly in Windows 11, quite doubtful that it will change in the future.

You can rip all these structures from WDK8 mfcs42ud.pdb, for unknown reasons this PDB has all of these. Maybe these can be also found somewhere in WDK or in other PDB files.

### RTL_VERIFIER_PROVIDER_DESCRIPTOR

```c
typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR {
  DWORD Length;
  PRTL_VERIFIER_DLL_DESCRIPTOR ProviderDlls;
  RTL_VERIFIER_DLL_LOAD_CALLBACK ProviderDllLoadCallback;
  RTL_VERIFIER_DLL_UNLOAD_CALLBACK ProviderDllUnloadCallback;
  PWSTR VerifierImage;
  DWORD VerifierFlags;
  DWORD VerifierDebug;
  PVOID RtlpGetStackTraceAddress;
  PVOID RtlpDebugPageHeapCreate;
  PVOID RtlpDebugPageHeapDestroy;
  RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK ProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR, *PRTL_VERIFIER_PROVIDER_DESCRIPTOR;
```

Main custom provider structure.

Significant members:

#### Length

The size of this data structure, in bytes. Set this member to sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR).

#### ProviderDlls

Pointer to array of RTL_VERIFIER_DLL_DESCRIPTOR type structures, describing dlls to be hooked.

#### ProviderDllLoadCallback

Pointer to a dlls loading callback, with the following format

```c
typedef VOID (NTAPI * RTL_VERIFIER_DLL_LOAD_CALLBACK) (PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);
```

This callback will be called before DLL_PROCESS_ATTACH event of any loading dll.

#### ProviderDllUnloadCallback

Pointer to dlls unloading callback, with the following format

```c
typedef VOID (NTAPI * RTL_VERIFIER_DLL_UNLOAD_CALLBACK) (PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);
```

This callback will be called before DLL_PROCESS_DETACH event of any unloading dll.

...

#### ProviderNtdllHeapFreeCallback

Pointer to callback called before any ntdll heap free, has the following format

```c
typedef VOID (NTAPI * RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK) (PVOID AllocationBase, SIZE_T AllocationSize);
```

### RTL_VERIFIER_DLL_DESCRIPTOR

```c
typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR {
  PWCHAR DllName;
  DWORD DllFlags;
  PVOID DllAddress;
  PRTL_VERIFIER_THUNK_DESCRIPTOR DllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR, *PRTL_VERIFIER_DLL_DESCRIPTOR;
```

Members:

#### PWCHAR DllName

Unicode name of dll which routines you want to filter. E.g. L"kernel32.dll"

#### DllFlags

Filled by verifier, do not use.

#### DllAddress

Filled by verifier, do not use.

#### DllThunks

Pointer to array of RTL_VERIFIER_THUNK_DESCRIPTOR structures, describing each hook.

### RTL_VERIFIER_THUNK_DESCRIPTOR

```c
typedef struct _RTL_VERIFIER_THUNK_DESCRIPTOR {
  PCHAR ThunkName;
  PVOID ThunkOldAddress;
  PVOID ThunkNewAddress;
} RTL_VERIFIER_THUNK_DESCRIPTOR, *PRTL_VERIFIER_THUNK_DESCRIPTOR;
```

Members:

#### ThunkName

ANSI name of routine to intercept. E.g. "CloseHandle"

#### ThunkOldAddress

Filled by verifier, do not change. There will be stored original address of hooked by IAT patching routine.

#### ThunkNewAddress

Pointer to hook handler. E.g. CloseHandleHook

### InitRoutine (DllMain)

```c
BOOL WINAPI InitRoutine(
  PVOID DllHandle,
  DWORD fdwReason,
  PRTL_VERIFIER_PROVIDER_DESCRIPTOR* pVPD
  )
{
  switch(fdwReason)
  {
  case DLL_PROCESS_ATTACH:
    LdrDisableThreadCalloutsForDll(DllHandle);
    break;
  case DLL_PROCESS_VERIFIER:
    RegisterProvider();
    *pVPD = &g_avrfProvider;
    Payload();
    break;
  default:
    break;
  }
  return TRUE;
}
```

The same DllMain but with usage of 3rd parameter and custom provider registration at new undocumented fdwReason.

### AVrf reason code for dll entry point

```c
#define DLL_PROCESS_VERIFIER 4
```

This event will occur **_before_** any other events.

## AVrf custom provider installation

Copy your provider dll to the %SystemRoot%\System32 directory. Note: For hooking into 32-bit processes on a 64-bit system, you have to use the %SystemRoot%\SysWOW64 directory. Administrator rights are required.


Install the provider dll for the specific application you want to debug, go to the IFEO key:
`HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\AppName` (Replace `AppName` with the name of the program, including extension). Note: For hooking into 32-bit processes on a 64-bit system, you have to use the `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options` key.

Here, Set the `VerifierDlls` value to the name of your dll (can be multiple), specifying extension is optional.

`"VerifierDlls"="mydll.dll"`

Enable Application Verifier for this application, in the same key.

`"GlobalFlag"=dword:00000100`

Where `0x00000100` is `FLG_APPLICATION_VERIFIER` -> [Enable application verifier](http://msdn.microsoft.com/en-us/library/Windows/hardware/ff542875(v=vs.85).aspx)

Example:

```reg
[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mytest.exe]
"VerifierDlls"="mydll.dll"
"GlobalFlag"=dword:00000100
```

## AVrf Custom provider example

This custom provider implements hooking of NtQuerySystemInformation with debug output of it result and Avrf dynamic-link libraries load callback example.

```c
#include "ntdll\ntdll.h"
#include "ntdll\ntstatus.h"

#define DLL_PROCESS_VERIFIER 4

typedef VOID (NTAPI * RTL_VERIFIER_DLL_LOAD_CALLBACK) (PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);
typedef VOID (NTAPI * RTL_VERIFIER_DLL_UNLOAD_CALLBACK) (PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved);
typedef VOID (NTAPI * RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK) (PVOID AllocationBase, SIZE_T AllocationSize);

typedef struct _RTL_VERIFIER_THUNK_DESCRIPTOR {
  PCHAR ThunkName;
  PVOID ThunkOldAddress;
  PVOID ThunkNewAddress;
} RTL_VERIFIER_THUNK_DESCRIPTOR, *PRTL_VERIFIER_THUNK_DESCRIPTOR;

typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR {
  PWCHAR DllName;
  DWORD DllFlags;
  PVOID DllAddress;
  PRTL_VERIFIER_THUNK_DESCRIPTOR DllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR, *PRTL_VERIFIER_DLL_DESCRIPTOR;

typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR {
  DWORD Length;
  PRTL_VERIFIER_DLL_DESCRIPTOR ProviderDlls;
  RTL_VERIFIER_DLL_LOAD_CALLBACK ProviderDllLoadCallback;
  RTL_VERIFIER_DLL_UNLOAD_CALLBACK ProviderDllUnloadCallback;
  PWSTR VerifierImage;
  DWORD VerifierFlags;
  DWORD VerifierDebug;
  PVOID RtlpGetStackTraceAddress;
  PVOID RtlpDebugPageHeapCreate;
  PVOID RtlpDebugPageHeapDestroy;
  RTL_VERIFIER_NTDLLHEAPFREE_CALLBACK ProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR, *PRTL_VERIFIER_PROVIDER_DESCRIPTOR;

static RTL_VERIFIER_THUNK_DESCRIPTOR avrfThunks[2];
static RTL_VERIFIER_DLL_DESCRIPTOR avrfDlls[2];
static RTL_VERIFIER_PROVIDER_DESCRIPTOR g_avrfProvider;

typedef NTSTATUS (NTAPI *pfnNtQuerySystemInformation)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT OPTIONAL PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    );

pfnNtQuerySystemInformation pNtQuerySystemInformation;

VOID NTAPI avrfLoadCallback(PWSTR DllName, PVOID DllBase, SIZE_T DllSize, PVOID Reserved)
{
  DbgPrint("VerifierLoadCallback - dll load %ws, DllBase = %p\n\r", DllName, DllBase);
}

NTSTATUS NTAPI NtQuerySystemInformationHook(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT OPTIONAL PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT OPTIONAL PULONG ReturnLength
    )
{
  NTSTATUS status;

  status = ((pfnNtQuerySystemInformation)(avrfThunks[0].ThunkOldAddress))(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

  DbgPrint("NtQuerySystemInformation(%d) = %lx\n\r", SystemInformationClass, status);
  return status;
}

VOID Payload()
{
  DbgPrint("DLL!Payload()\n\r");
}

VOID RegisterProvider(
  VOID
  )
{
  DbgPrint("DLL!RegisterProvider\n\r");

  avrfThunks[0].ThunkName = "RtlQueryElevationFlags";
  avrfThunks[0].ThunkOldAddress = NULL;
  avrfThunks[0].ThunkNewAddress = &RtlQueryElevationFlagsHook;

  avrfDlls[0].DllName = L"ntdll.dll";
  avrfDlls[0].DllFlags = 0;
  avrfDlls[0].DllAddress = NULL;
  avrfDlls[0].DllThunks = avrfThunks;

  RtlSecureZeroMemory(&g_avrfProvider, sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR));
  g_avrfProvider.Length = sizeof(RTL_VERIFIER_PROVIDER_DESCRIPTOR);
  g_avrfProvider.ProviderDlls = avrfDlls;
  g_avrfProvider.ProviderDllLoadCallback = (RTL_VERIFIER_DLL_LOAD_CALLBACK)&avrfLoadCallback;
}

BOOL WINAPI InitRoutine(
  PVOID DllHandle,
  DWORD fdwReason,
  PRTL_VERIFIER_PROVIDER_DESCRIPTOR* pVPD
  )
{
  switch(fdwReason)
  {
  case DLL_PROCESS_ATTACH:
    DbgPrint("DLL!DLL_PROCESS_ATTACH\n\r");
    LdrDisableThreadCalloutsForDll(DllHandle);
    break;
  case DLL_PROCESS_DETACH:
    DbgPrint("DLL!DLL_PROCESS_DETACH\n\r");
    break;
  case DLL_PROCESS_VERIFIER:
    DbgPrint("DLL!DLL_PROCESS_VERIFIER\n\r");
    RegisterProvider();
    *pVPD = &g_avrfProvider;
    Payload();
    break;
  default:
    break;
  }
  return TRUE;
}
```

Execution trace result (Dependency Walker), custom provider name - "dll.dll"

```txt
Options Selected:
     Simulate ShellExecute by inserting any App Paths directories into the PATH environment variable.
     Log thread information.
     Use simple thread numbers instead of actual thread IDs.
     Log first chance exceptions.
     Log debug output messages.
     Use full paths when logging file names.
     Log a time stamp with each line of log.
     Automatically open and profile child processes.
--------------------------------------------------------------------------------

00:00:00.000: Started "c:\verifier_test\VRTEST.EXE" (process 0x1580) at address 0x00000000FFC20000 by thread 1.
00:00:00.000: Loaded "c:\windows\system32\NTDLL.DLL" at address 0x0000000076F40000 by thread 1.
00:00:00.015: Loaded "c:\windows\system32\VERIFIER.DLL" at address 0x000007FEF93B0000 by thread 1.
00:00:00.015: Page heap: pid 0x1580: page heap enabled with flags 0x2.
00:00:00.015: AVRF: VRTEST.EXE: pid 0x1580: flags 0x48004: application verifier enabled
00:00:00.031: Loaded "c:\windows\system32\DLL.DLL" at address 0x000007FEF9D50000 by thread 1.
00:00:00.031: DLL!DLL_PROCESS_VERIFIER
00:00:00.031: DLL!RegisterProvider
00:00:00.031: DLL!Payload()
00:00:00.031: DLL!DLL_PROCESS_ATTACH
00:00:00.031: Loaded "c:\windows\system32\KERNEL32.DLL" at address 0x0000000076E20000 by thread 1.
00:00:00.046: Loaded "c:\windows\system32\KERNELBASE.DLL" at address 0x000007FEFCDD0000 by thread 1.
00:00:00.046: VerifierLoadCallback - dll load KERNELBASE.dll, DllBase = 000007FEFCDD0000
00:00:00.046: VerifierLoadCallback - dll load kernel32.dll, DllBase = 0000000076E20000
00:00:00.046: DLL!DLL_PROCESS_ATTACH
00:00:00.046: NtQuerySystemInformation(50) = 0
00:00:00.046: NtQuerySystemInformation(0) = 0
00:00:00.046: NtQuerySystemInformation(1) = 0
00:00:00.046: NtQuerySystemInformation(0) = 0
00:00:00.046: NtQuerySystemInformation(1) = 0
00:00:00.046: Loaded "c:\windows\system32\USER32.DLL" at address 0x0000000076D20000 by thread 1.
00:00:00.046: Loaded "c:\windows\system32\GDI32.DLL" at address 0x000007FEFEBD0000 by thread 1.
00:00:00.046: Loaded "c:\windows\system32\LPK.DLL" at address 0x000007FEFF240000 by thread 1.
00:00:00.046: Loaded "c:\windows\system32\USP10.DLL" at address 0x000007FEFDAE0000 by thread 1.
00:00:00.046: Loaded "c:\windows\system32\MSVCRT.DLL" at address 0x000007FEFEF70000 by thread 1.
00:00:00.062: VerifierLoadCallback - dll load msvcrt.dll, DllBase = 000007FEFEF70000
00:00:00.062: VerifierLoadCallback - dll load USP10.dll, DllBase = 000007FEFDAE0000
00:00:00.062: VerifierLoadCallback - dll load LPK.dll, DllBase = 000007FEFF240000
00:00:00.062: VerifierLoadCallback - dll load GDI32.dll, DllBase = 000007FEFEBD0000
00:00:00.062: VerifierLoadCallback - dll load USER32.dll, DllBase = 0000000076D20000
00:00:00.062: Loaded "c:\windows\system32\SHELL32.DLL" at address 0x000007FEFDD90000 by thread 1.
00:00:00.062: Loaded "c:\windows\system32\SHLWAPI.DLL" at address 0x000007FEFDD10000 by thread 1.
00:00:00.062: VerifierLoadCallback - dll load SHLWAPI.dll, DllBase = 000007FEFDD10000
00:00:00.062: VerifierLoadCallback - dll load SHELL32.dll, DllBase = 000007FEFDD90000
00:00:00.062: VerifierLoadCallback - dll load VRTEST.EXE, DllBase = 00000000FFC20000
00:00:00.062: Entrypoint reached. All implicit modules have been loaded.
00:00:00.062: Loaded "c:\windows\system32\APPHELP.DLL" at address 0x000007FEFCB70000 by thread 1.
00:00:00.078: VerifierLoadCallback - dll load apphelp.dll, DllBase = 000007FEFCB70000
00:00:00.078: NtQuerySystemInformation(1) = 0
00:00:00.078: Loaded "c:\windows\apppatch\apppatch64\ACGENRAL.DLL" at address 0x000007FEF2BA0000 by thread 1.
00:00:00.078: Loaded "c:\windows\system32\SSPICLI.DLL" at address 0x000007FEFCB40000 by thread 1.
00:00:00.078: Loaded "c:\windows\system32\RPCRT4.DLL" at address 0x000007FEFF010000 by thread 1.
00:00:00.078: VerifierLoadCallback - dll load RPCRT4.dll, DllBase = 000007FEFF010000
00:00:00.078: VerifierLoadCallback - dll load SspiCli.dll, DllBase = 000007FEFCB40000
00:00:00.078: Loaded "c:\windows\system32\OLE32.DLL" at address 0x000007FEFD470000 by thread 1.
00:00:00.093: VerifierLoadCallback - dll load ole32.dll, DllBase = 000007FEFD470000
00:00:00.093: Loaded "c:\windows\system32\SFC.DLL" at address 0x0000000072F00000 by thread 1.
00:00:00.093: VerifierLoadCallback - dll load sfc.dll, DllBase = 0000000072F00000
00:00:00.093: Loaded "c:\windows\system32\SFC_OS.DLL" at address 0x000007FEF84B0000 by thread 1.
00:00:00.093: VerifierLoadCallback - dll load sfc_os.DLL, DllBase = 000007FEF84B0000
00:00:00.093: Loaded "c:\windows\system32\USERENV.DLL" at address 0x000007FEFCF60000 by thread 1.
00:00:00.109: Loaded "c:\windows\system32\PROFAPI.DLL" at address 0x000007FEFCD70000 by thread 1.
00:00:00.109: VerifierLoadCallback - dll load profapi.dll, DllBase = 000007FEFCD70000
00:00:00.109: VerifierLoadCallback - dll load USERENV.dll, DllBase = 000007FEFCF60000
00:00:00.109: Loaded "c:\windows\system32\DWMAPI.DLL" at address 0x000007FEFB0A0000 by thread 1.
00:00:00.109: VerifierLoadCallback - dll load dwmapi.dll, DllBase = 000007FEFB0A0000
00:00:00.109: Loaded "c:\windows\system32\ADVAPI32.DLL" at address 0x000007FEFDC30000 by thread 1.
00:00:00.109: Loaded "c:\windows\system32\SECHOST.DLL" at address 0x000007FEFEF50000 by thread 1.
00:00:00.124: VerifierLoadCallback - dll load sechost.dll, DllBase = 000007FEFEF50000
00:00:00.124: VerifierLoadCallback - dll load ADVAPI32.dll, DllBase = 000007FEFDC30000
00:00:00.124: Loaded "c:\windows\system32\MPR.DLL" at address 0x000007FEF80F0000 by thread 1.
00:00:00.124: VerifierLoadCallback - dll load MPR.dll, DllBase = 000007FEF80F0000
00:00:00.124: VerifierLoadCallback - dll load AcGenral.DLL, DllBase = 000007FEF2BA0000
00:00:00.124: NtQuerySystemInformation(0) = 0
00:00:00.124: Loaded "c:\windows\system32\IMM32.DLL" at address 0x000007FEFDA90000 by thread 1.
00:00:00.140: Loaded "c:\windows\system32\MSCTF.DLL" at address 0x000007FEFD680000 by thread 1.
00:00:00.140: VerifierLoadCallback - dll load MSCTF.dll, DllBase = 000007FEFD680000
00:00:00.140: VerifierLoadCallback - dll load IMM32.DLL, DllBase = 000007FEFDA90000
00:00:00.140: NtQuerySystemInformation(0) = 0
00:00:00.140: NtQuerySystemInformation(0) = 0
00:00:00.140: NtQuerySystemInformation(1) = 0
00:00:00.140: NtQuerySystemInformation(0) = 0
00:00:00.140: NtQuerySystemInformation(1) = 0
00:00:00.156: DLL!DLL_PROCESS_DETACH
00:00:00.156: Exited "c:\verifier_test\VRTEST.EXE" (process 0x1580) with code 0 (0x0) by thread 1.
```

___

## Links

1) MSFT: [Reiley Yang - A Debugging Approach to IFEO](https://blogs.msdn.microsoft.com/reiley/2011/07/29/a-debugging-approach-to-ifeo/)

2) MSFT: [Reiley Yang - A Debugging Approach to Application Verifier](https://blogs.msdn.microsoft.com/reiley/2012/08/17/a-debugging-approach-to-application-verifier/)

3) Unknown source vanished in time (c) 2004.

___

Originally at [kernelmode.info](https://www.kernelmode.info/forum/viewtopic.php?f=15&t=3418) by EP_X0FF / hfiref0x ([archived kernelmode.info](https://www.kernelmode.info/forum/viewtopicf4c5.html?f=15&t=3418#), [archive](http://archivecaslytosk.onion/8R9ml)). Broken links were updated, has been reworded to make it easier to understand.
