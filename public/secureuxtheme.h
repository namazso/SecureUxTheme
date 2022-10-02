#ifndef SECUREUXTHEME_INCLUDED
#define SECUREUXTHEME_INCLUDED 1

#include <Windows.h>

EXTERN_C_START

/**
 * @brief Sets the dll to use for an architecture, needed for update check and install.
 * @param data Byte data for the dll
 * @param size Size of data
 * @param arch Architecture this dll belongs to, one of the @c IMAGE_FILE_MACHINE_ macros
 */
void secureuxtheme_set_dll_for_arch(LPCVOID data, SIZE_T size, ULONG arch);

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
 * @brief Rename the DefaultColors key to DefaultColors_backup, and recreate it as empty.
 */
#define SECUREUXTHEME_INSTALL_RENAME_DEFAULTCOLORS  (ULONG)(1 << 3)

/**
 * @brief Install SecureUxTheme.
 * @param install_flags Install flags
 * @return A HRESULT, either from Windows or custom
 */
HRESULT secureuxtheme_install(ULONG install_flags);

/**
 * @brief Install SecureUxTheme for a specific executable.
 * @param executable Executable name
 * @return A HRESULT, either from Windows or custom
 */
HRESULT secureuxtheme_hook_add(LPCWSTR executable);

/**
 * @brief Uninstall SecureUxTheme for a specific executable.
 * @param executable Executable name
 * @return A HRESULT, either from Windows or custom
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
 * @return A HRESULT, either from Windows or custom
 */
HRESULT secureuxtheme_uninstall(void);

EXTERN_C_END

#endif
