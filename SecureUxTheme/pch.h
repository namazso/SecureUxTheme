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

#define _NO_CRT_STDIO_INLINE 1
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS

#define PHNT_VERSION PHNT_WINDOWS_NEW

#include <phnt_windows.h>

#include <phnt.h>

#include <WinCrypt.h>

#include <intrin.h>

#include "verifier.h"

#include <algorithm>
#include <cstring>
#include <type_traits>

typedef PVOID(NTAPI* PDELAYLOAD_FAILURE_SYSTEM_ROUTINE)(
  _In_ PCSTR DllName,
  _In_ PCSTR ProcName
);

#undef RTL_CONSTANT_STRING
#define RTL_CONSTANT_STRING(s)                                                                     \
  {                                                                                                \
    sizeof(s) - sizeof((s)[0]),                                                                    \
    sizeof(s),                                                                                     \
    (std::add_pointer_t<std::remove_const_t<std::remove_pointer_t<std::decay_t<decltype(s)>>>>)(s) \
  }

#define DebugPrint(str, ...) DbgPrintEx((ULONG)101u, 3u, "[SecureUxTheme] " __FUNCTION__ ": " str, ##__VA_ARGS__)
