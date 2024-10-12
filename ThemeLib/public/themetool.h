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
#ifndef THEMETOOL_INCLUDED
#define THEMETOOL_INCLUDED 1

#include <Windows.h>

EXTERN_C_START

typedef struct ITheme ITheme;
typedef struct IThemeManager2 IThemeManager2;

/**
 * @brief Initialize themeing features.
 * @return A HRESULT
 * @warning This patches CryptVerifySignatureW in the process, which means any signature verification will pass.
 */
HRESULT themetool_init(void);

/**
 * @brief Gets the IThemeManager2 interface, use at own risk.
 * @return IThemeManager2 interface
 * @warning This is intentionally an opaque pointer, as it's your job to keep the interface up to date if you wish to
 *          use it. Use the other exported functions for management with guarantees.
 */
IThemeManager2* themetool_get_manager(void);

/**
 * @brief Get count of themes, according to Windows.
 * @param count Count of themes
 * @return A HRESULT
 */
HRESULT themetool_get_theme_count(PULONG count);

/**
 * @brief Get a specific theme.
 * @param idx Index of theme to get
 * @param theme Output opaque pointer
 * @return A HRESULT
 * @warning This is intentionally an opaque pointer, as it's your job to keep the interface up to date if you wish to
 *          use it. Use the other exported functions for management with guarantees.
 */
HRESULT themetool_get_theme(ULONG idx, ITheme** theme);

/**
 * @brief Ignore background.
 */
#define THEMETOOL_APPLY_FLAG_IGNORE_BACKGROUND    (ULONG)(1 << 0)
/**
 * @brief Ignore cursor.
 */
#define THEMETOOL_APPLY_FLAG_IGNORE_CURSOR        (ULONG)(1 << 1)
/**
 * @brief Ignore desktop icons.
 */
#define THEMETOOL_APPLY_FLAG_IGNORE_DESKTOP_ICONS (ULONG)(1 << 2)
/**
 * @brief Ignore color accent.
 */
#define THEMETOOL_APPLY_FLAG_IGNORE_COLOR         (ULONG)(1 << 3)
/**
 * @brief Ignore sounds.
 */
#define THEMETOOL_APPLY_FLAG_IGNORE_SOUND         (ULONG)(1 << 4)
/**
 * @brief Ignore screensaver.
 */
#define THEMETOOL_APPLY_FLAG_IGNORE_SCREENSAVER   (ULONG)(1 << 5)
/**
 * @brief Unknown, maybe ignore window metrics.
 */
#define THEMETOOL_APPLY_FLAG_UNKNOWN              (ULONG)(1 << 6)
/**
 * @brief Unknown.
 */
#define THEMETOOL_APPLY_FLAG_UNKNOWN2             (ULONG)(1 << 7)
/**
 * @brief Suppress hourglass.
 */
#define THEMETOOL_APPLY_FLAG_NO_HOURGLASS         (ULONG)(1 << 8)

/**
 * @brief Unknown, seems to suppress hourglass.
 */
#define THEMETOOL_PACK_FLAG_UNKNOWN1              (ULONG)(1 << 0)
/**
 * @brief Unknown, seems to suppress hourglass.
 */
#define THEMETOOL_PACK_FLAG_UNKNOWN2              (ULONG)(1 << 1)
/**
 * @brief Hides all dialogs and prevents sound.
 */
#define THEMETOOL_PACK_FLAG_SILENT                (ULONG)(1 << 2)
/**
 * @brief Roamed.
 */
#define THEMETOOL_PACK_FLAG_ROAMED                (ULONG)(1 << 3)

/**
 * @brief Set active theme.
 * @param parent Parent window that caused this, optional
 * @param theme_idx Theme index
 * @param apply_now_not_only_registry If TRUE, theme is applied, otherwise only registry is changed
 * @param apply_flags Combination of the THEMETOOL_APPLY_FLAG_ macros
 * @param pack_flags Combination of the THEMETOOL_PACK_FLAG_ macros
 * @return A HRESULT
 */
HRESULT themetool_set_active(
  HWND parent,
  ULONG theme_idx,
  BOOLEAN apply_now_not_only_registry,
  ULONG apply_flags,
  ULONG pack_flags
);

/**
 * @brief Get display name of a theme.
 * @param theme Opaque theme pointer
 * @param out Output buffer
 * @param cch Output buffer length
 * @return A HRESULT
 * @retval HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) Buffer too small
 */
HRESULT themetool_theme_get_display_name(ITheme* theme, LPWSTR out, SIZE_T cch);

/**
 * @brief Get visual style path of a theme.
 * @param theme Opaque theme pointer
 * @param out Output buffer
 * @param cch Output buffer length
 * @return A HRESULT
 * @retval HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) Buffer too small
 */
HRESULT themetool_theme_get_vs_path(ITheme* theme, LPWSTR out, SIZE_T cch);

/**
 * @brief Release (free) a theme pointer.
 * @param theme Opaque theme pointer
 */
void themetool_theme_release(ITheme* theme);

/**
 * @brief Check if a signature is correct (but not if it's valid).
 * @param path Path to file
 * @return A HRESULT
 * @retval E_FAIL The signature was incorrect or not found
 * @retval S_OK The signature was present
 */
HRESULT themetool_signature_check(LPCWSTR path);

/**
 * @brief Add an invalid signature to a theme.
 * @param path Path to file
 * @return A HRESULT
 */
HRESULT themetool_signature_fix(LPCWSTR path);

EXTERN_C_END

#endif