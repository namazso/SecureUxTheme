/* SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
 * Copyright (C) 2024  namazso <admin@namazso.eu>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
#ifndef SECUREUXTHEME_INCLUDED
#define SECUREUXTHEME_INCLUDED 1

#include <Windows.h>

EXTERN_C_START

/**
 * @brief The dll is installed and set to load in winlogon.exe.
 */
#define SECUREUXTHEME_STATE_INSTALLED       (ULONG)(1 << 0)
/**
 * @brief The dll content matches the one given for this architecture.
 */
#define SECUREUXTHEME_STATE_CURRENT         (ULONG)(1 << 1)
/**
 * @brief Is loaded in this session.
 */
#define SECUREUXTHEME_STATE_LOADED          (ULONG)(1 << 2)
/**
 * @brief Set to load into explorer.exe.
 */
#define SECUREUXTHEME_STATE_EXPLORER_HOOKED (ULONG)(1 << 3)
/**
 * @brief Set to load into SystemSettings.exe.
 */
#define SECUREUXTHEME_STATE_SETTINGS_HOOKED (ULONG)(1 << 4)
/**
 * @brief Set to load into LogonUI.exe.
 */
#define SECUREUXTHEME_STATE_LOGONUI_HOOKED  (ULONG)(1 << 5)

/**
 * @brief Test current install and load state.
 * @return A combination of @c SECUREUXTHEME_STATE_ flags
 */
ULONG secureuxtheme_get_state_flags(void);

/**
 * @brief Install hook for explorer.exe.
 */
#define SECUREUXTHEME_INSTALL_HOOK_EXPLORER         (ULONG)(1 << 0)
/**
 * @brief Install hook for SystemSettings.exe.
 */
#define SECUREUXTHEME_INSTALL_HOOK_SETTINGS         (ULONG)(1 << 1)
/**
 * @brief Install hook for LogonUI.exe.
 */
#define SECUREUXTHEME_INSTALL_HOOK_LOGONUI          (ULONG)(1 << 2)
/**
 * @brief Delete the DefaultColors values.
 */
#define SECUREUXTHEME_INSTALL_DELETE_DEFAULTCOLORS  (ULONG)(1 << 3)

/**
 * @brief Install SecureUxTheme.
 * @param install_flags Install flags
 * @return A HRESULT
 */
HRESULT secureuxtheme_install(ULONG install_flags);

/**
 * @brief Install SecureUxTheme for a specific executable.
 * @param executable Executable name
 * @return A HRESULT
 */
HRESULT secureuxtheme_hook_add(LPCWSTR executable);

/**
 * @brief Uninstall SecureUxTheme for a specific executable.
 * @param executable Executable name
 * @return A HRESULT
 */
HRESULT secureuxtheme_hook_remove(LPCWSTR executable);

/**
 * @brief Test if an executable is hooked.
 * @param executable Executable name
 * @return Whether hooks are installed for the executable
 */
BOOLEAN secureuxtheme_hook_test(LPCWSTR executable);

/**
 * @brief Uninstall all hooks and delete the dll.
 * @return A HRESULT
 */
HRESULT secureuxtheme_uninstall(void);

EXTERN_C_END

#endif
