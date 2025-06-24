# SecureUxTheme - A secure boot compatible in-memory UxTheme patcher
# Copyright (C) 2025  namazso <admin@namazso.eu>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

cmake_minimum_required(VERSION 3.16)

project(SecureUxTheme)

set(CI_VERSION "(unknown)" CACHE STRING "Version string")
set(CI_VERSION_MAJOR "0" CACHE STRING "Version major number")
set(CI_VERSION_MINOR "0" CACHE STRING "Version minor number")
set(CI_VERSION_PATCH "0" CACHE STRING "Version patch number")

set(SIGN_SCRIPT "" CACHE STRING "Signing script, called like <script> <input> <output>")

add_compile_options(
        "$<$<NOT:$<CONFIG:Debug>>:/Zi>"
        /utf-8
        /d1nodatetime
        /W4
        /wd4201 # C4201: nonstandard extension used: nameless struct/union
        /wd4471 # C4471: a forward declaration of an unscoped enumeration must have an underlying type
        /wd4324 # C4324: structure was padded due to alignment specifier
        /WX
)

add_link_options(
        "$<$<NOT:$<CONFIG:Debug>>:/DEBUG>"
        "$<$<NOT:$<CONFIG:Debug>>:/OPT:REF>"
        "$<$<NOT:$<CONFIG:Debug>>:/OPT:ICF=10>"
        /Brepro
        /PDBALTPATH:%_PDB%
        /FILEALIGN:0x1000
        /NOVCFEATURE
        /NOCOFFGRPINFO
)

add_compile_definitions(
        UNICODE
        _UNICODE
        "CI_VERSION=\"${CI_VERSION}\""
        "CI_VERSION_MAJOR=${CI_VERSION_MAJOR}"
        "CI_VERSION_MINOR=${CI_VERSION_MINOR}"
        "CI_VERSION_PATCH=${CI_VERSION_PATCH}"
)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)
FetchContent_Declare(phnt
        GIT_REPOSITORY "https://github.com/winsiderss/phnt"
        GIT_TAG fc1f96ee976635f51faa89896d1d805eb0586350
)
FetchContent_MakeAvailable(phnt)

add_library(SecureUxTheme SHARED
        SecureUxTheme/avrf.cpp
        SecureUxTheme/hooks.cpp
        SecureUxTheme/chores.cpp
)
target_precompile_headers(SecureUxTheme PRIVATE
        SecureUxTheme/pch.h
)
target_link_libraries(SecureUxTheme PRIVATE
        phnt::phnt
        ntdll.lib
        ntdllp.lib
)
target_compile_options(SecureUxTheme PRIVATE
        /GS-
        /Oy-
)
target_link_options(SecureUxTheme PRIVATE
        /ENTRY:DllMain
)
set_target_properties(SecureUxTheme PROPERTIES OUTPUT_NAME "SecureUxTheme4")

add_library(ThemeUiProxy SHARED ThemeUiProxy/dll.cpp)

target_link_libraries(ThemeUiProxy PRIVATE phnt::phnt ntdll.lib ntdllp.lib)
target_compile_options(ThemeUiProxy PRIVATE
        /GS-
)
target_link_options(ThemeUiProxy PRIVATE
        /ENTRY:DllMain
)

if(DEFINED BUILD_AS_ARM64X)
    set(ARM64X_TARGETS SecureUxTheme ThemeUiProxy)
    include("arm64x.cmake")
endif()
