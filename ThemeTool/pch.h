// SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
// Copyright (C) 2024  namazso <admin@namazso.eu>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#pragma once
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS

#define PHNT_VERSION PHNT_WINBLUE

#include <phnt_windows.h>

#include <phnt.h>

#include "resource.h"

#include <cguid.h>

#include <atlbase.h>
#include <CommCtrl.h>
#include <Psapi.h>
#include <shellapi.h>
#include <windowsx.h>
#include <wtsapi32.h>

#include <list>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include <secureuxtheme.h>
#include <themetool.h>
