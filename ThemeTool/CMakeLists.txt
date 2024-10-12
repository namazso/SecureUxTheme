cmake_minimum_required(VERSION 3.16)

project(ThemeTool)

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
set(CI_VERSION "(unknown)" CACHE STRING "Version string")
set(CI_VERSION_MAJOR "0" CACHE STRING "Version major number")
set(CI_VERSION_MINOR "0" CACHE STRING "Version minor number")
set(CI_VERSION_PATCH "0" CACHE STRING "Version patch number")
add_compile_definitions(
        UNICODE
        _UNICODE
        "CI_VERSION=\"${CI_VERSION}\""
        "CI_VERSION_MAJOR=${CI_VERSION_MAJOR}"
        "CI_VERSION_MINOR=${CI_VERSION_MINOR}"
        "CI_VERSION_PATCH=${CI_VERSION_PATCH}"
)

set(CMAKE_CXX_STANDARD 20)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_library(ThemeLib STATIC
        lib/install.cpp
        lib/signature.cpp
        lib/theme.cpp
)

target_include_directories(ThemeLib PUBLIC lib/public)

add_library(ThemeDll SHARED
        dll/dllmain.cpp
        dll/exports.def
        embedded/embedded.rc
)

target_link_libraries(ThemeDll PRIVATE ThemeLib)

add_executable(ThemeTool WIN32
        exe/main.cpp
        exe/MainDialog.cpp
        exe/utl.cpp
        exe/ThemeTool.rc
        embedded/embedded.rc
)

target_precompile_headers(ThemeTool PRIVATE exe/pch.h)

target_link_libraries(ThemeTool PRIVATE ThemeLib)
