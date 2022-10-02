//  SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
//  Copyright (C) 2022  namazso <admin@namazso.eu>
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

#include <Windows.h>
#include "resource.h"
#include <utility>
#include "../public/secureuxtheme.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

std::pair<LPCVOID, SIZE_T> get_resource(HMODULE mod, WORD type, WORD id)
{
  const auto rc = FindResource(
    mod,
    MAKEINTRESOURCE(id),
    MAKEINTRESOURCE(type)
  );
  if (!rc)
    return { nullptr, 0 };
  const auto rc_data = LoadResource(mod, rc);
  const auto size = SizeofResource(mod, rc);
  if (!rc_data)
    return { nullptr, 0 };
  const auto data = static_cast<const void*>(LockResource(rc_data));
  return { data, size };
}

void bind_resource_to_arch(HMODULE mod, WORD resid, WORD arch)
{
  const auto res = get_resource(mod, 256, resid);
  secureuxtheme_set_dll_for_arch(res.first, res.second, arch);
}

void do_init(HMODULE mod)
{
  bind_resource_to_arch(mod, IDR_SECUREUXTHEME_DLL_X86, IMAGE_FILE_MACHINE_I386);
  bind_resource_to_arch(mod, IDR_SECUREUXTHEME_DLL_X64, IMAGE_FILE_MACHINE_AMD64);
  bind_resource_to_arch(mod, IDR_SECUREUXTHEME_DLL_ARM64, IMAGE_FILE_MACHINE_ARM64);
}

BOOL APIENTRY DllMain(
  HMODULE mod,
  DWORD reason,
  LPVOID reserved
)
{
  if (reason == DLL_PROCESS_ATTACH)
    do_init(mod);
  return TRUE;
}
