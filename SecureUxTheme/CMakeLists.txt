cmake_minimum_required(VERSION 3.16)

project(SecureUxTheme)

add_compile_options("$<$<NOT:$<CONFIG:Debug>>:/Zi>")
add_link_options("$<$<NOT:$<CONFIG:Debug>>:/DEBUG>")
add_link_options("$<$<NOT:$<CONFIG:Debug>>:/OPT:REF>")
add_link_options("$<$<NOT:$<CONFIG:Debug>>:/OPT:ICF>")

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(phnt)

add_library(SecureUxTheme SHARED avrf.cpp)

target_link_libraries(SecureUxTheme PRIVATE phnt::phnt ntdll.lib ntdllp.lib)
target_compile_options(SecureUxTheme PRIVATE
        /GS-
        /utf-8
        /d1nodatetime
        /W4
        /wd4201 # C4201: nonstandard extension used: nameless struct/union
        /wd4471 # C4471: a forward declaration of an unscoped enumeration must have an underlying type
        /wd4324 # C4324: structure was padded due to alignment specifier
        /WX
)
target_link_options(SecureUxTheme PRIVATE
        /NODEFAULTLIB
        /ENTRY:DllMain
        /Brepro
        /PDBALTPATH:%_PDB%
        /FILEALIGN:0x1000
        /NOVCFEATURE
        /NOCOFFGRPINFO
)
