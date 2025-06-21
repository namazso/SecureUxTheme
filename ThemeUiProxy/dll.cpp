//  SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
//  Copyright (C) 2024  namazso <admin@namazso.eu>
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

#define _NO_CRT_STDIO_INLINE 1
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS

#define PHNT_VERSION PHNT_WINDOWS_NEW

#include <phnt_windows.h>

#include <phnt.h>

#pragma comment(linker, "/EXPORT:DllCanUnloadNow=themeui.DllCanUnloadNow,PRIVATE")
#pragma comment(linker, "/EXPORT:DllGetClassObject=themeui.DllGetClassObject,PRIVATE")

BOOL WINAPI DllMain(PVOID, DWORD reason, PVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    UNICODE_STRING dll{};
    RtlInitUnicodeString(&dll, L"SecureUxTheme.dll");
    PVOID handle{};
    // Note: LoadLibrary in DllMain has way too many issues by default. The only reason this is okay here is
    // that we know that this DLL will only use ntdll functions, which is already loaded in every process.
    LdrLoadDll((PWCH)(1 | LOAD_LIBRARY_SEARCH_SYSTEM32), nullptr, &dll, &handle);
  }
  return TRUE;
}