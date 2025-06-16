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

add_subdirectory(phnt)

add_library(SecureUxTheme SHARED SecureUxTheme/avrf.cpp)

target_link_libraries(SecureUxTheme PRIVATE phnt::phnt ntdll.lib ntdllp.lib)
target_compile_options(SecureUxTheme PRIVATE
        /GS-
)
target_link_options(SecureUxTheme PRIVATE
        /NODEFAULTLIB
        /ENTRY:DllMain
)

set(SECUREUXTHEME_SIGNED_PATH "${CMAKE_CURRENT_BINARY_DIR}/SecureUxTheme.signed.dll")
set(SECUREUXTHEME_HEADER_DIR "${CMAKE_CURRENT_BINARY_DIR}/SecureUxTheme_header")
set(SECUREUXTHEME_HEADER_PATH "${SECUREUXTHEME_HEADER_DIR}/SecureUxTheme.dll.h")

file(MAKE_DIRECTORY "${SECUREUXTHEME_HEADER_DIR}")

add_library(SecureUxTheme_header INTERFACE)
target_sources(SecureUxTheme_header PUBLIC
        FILE_SET HEADERS
        BASE_DIRS "${CMAKE_CURRENT_BINARY_DIR}/SecureUxTheme_header"
        FILES "${SECUREUXTHEME_HEADER_PATH}"
)
target_include_directories(SecureUxTheme_header INTERFACE "${SECUREUXTHEME_HEADER_DIR}")

if ("${SIGN_SCRIPT}" STREQUAL "")
    add_custom_command(
            OUTPUT "${SECUREUXTHEME_SIGNED_PATH}"
            COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:SecureUxTheme>" "${SECUREUXTHEME_SIGNED_PATH}"
            DEPENDS "$<TARGET_FILE:SecureUxTheme>"
            VERBATIM
    )
else ()
    add_custom_command(
            OUTPUT "${SECUREUXTHEME_SIGNED_PATH}"
            COMMAND "${SIGN_SCRIPT}"
            "$<TARGET_FILE:SecureUxTheme>"
            "${SECUREUXTHEME_SIGNED_PATH}"
            DEPENDS "$<TARGET_FILE:SecureUxTheme>"
            VERBATIM
    )
endif ()

add_custom_command(
        OUTPUT "${SECUREUXTHEME_HEADER_PATH}"
        COMMAND powershell -NoProfile -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/bin2h.ps1"
        "${SECUREUXTHEME_SIGNED_PATH}"
        "${SECUREUXTHEME_HEADER_PATH}"
        DEPENDS "${SECUREUXTHEME_SIGNED_PATH}"
        VERBATIM
)

add_library(ThemeLib STATIC
        ThemeLib/install.cpp
        ThemeLib/signature.cpp
        ThemeLib/theme.cpp
)
target_link_libraries(ThemeLib PRIVATE SecureUxTheme_header phnt::phnt)
target_include_directories(ThemeLib PUBLIC ThemeLib/public)

add_library(ThemeDll SHARED
        ThemeDll/dllmain.cpp
        ThemeDll/exports.def
)

target_link_libraries(ThemeDll PRIVATE ThemeLib)

add_executable(ThemeTool WIN32
        ThemeTool/main.cpp
        ThemeTool/MainDialog.cpp
        ThemeTool/utl.cpp
        ThemeTool/ThemeTool.rc
)
target_precompile_headers(ThemeTool PRIVATE ThemeTool/pch.h)

target_link_libraries(ThemeTool PRIVATE
        ThemeLib
        phnt::phnt
)
