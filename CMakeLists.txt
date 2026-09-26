# 3.28 for EXCLUDE_FROM_ALL in FetchContent_Declare, which keeps Catch2's own
# extras out of the default build.
cmake_minimum_required(VERSION 3.28)

# ASM_MASM is for the two tiny x86/x64 exception stubs in the executable; MSVC
# has no inline asm for x64. It is not used by the core library or the tests.
project(DebugBench VERSION 1.0.0 LANGUAGES C CXX ASM_MASM)

if(NOT MSVC)
    message(FATAL_ERROR "debug-bench uses Windows anti-debug techniques and builds with MSVC only.")
endif()

get_property(_db_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(NOT _db_multi_config AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Static CRT, so a released binary runs on a clean Windows install with no
# Visual C++ redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

option(DBGBENCH_BUILD_TESTS "Build the unit tests" ON)
option(DBGBENCH_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(DBGBENCH_BUILD_X32 "From a 64-bit configure, also build the 32-bit executable" ON)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(DBGBENCH_ARCH x64)
else()
    set(DBGBENCH_ARCH x32)
endif()

# ---------------------------------------------------------------------------
# Warnings, first-party targets only
# ---------------------------------------------------------------------------

# Guarded to C and C++ so the flags are not passed to the MASM assembler, which
# rejects them.
add_library(dbench_warnings INTERFACE)
target_compile_options(dbench_warnings INTERFACE
    $<$<COMPILE_LANGUAGE:C,CXX>:/W4;/permissive-;/Zc:__cplusplus;/utf-8>)
if(DBGBENCH_WARNINGS_AS_ERRORS)
    target_compile_options(dbench_warnings INTERFACE $<$<COMPILE_LANGUAGE:C,CXX>:/WX>)
endif()

# ---------------------------------------------------------------------------
# dbench_core: the catalog, the decision logic, and the table/JSON reporter.
# No Windows header is included here, so the tests link the real logic and
# drive it with a fake, with no debugger, no admin and no target process.
# ---------------------------------------------------------------------------

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/resources/Version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/Version.h
    @ONLY
)

add_library(dbench_core STATIC
    src/core/Checks.cpp
    src/core/Cli.cpp
    src/core/Report.cpp
)
target_compile_features(dbench_core PUBLIC cxx_std_20)
target_include_directories(dbench_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)
target_link_libraries(dbench_core PRIVATE dbench_warnings)

# ---------------------------------------------------------------------------
# The executable: the live Windows probe plus the command-line front end.
# ---------------------------------------------------------------------------

if(DBGBENCH_ARCH STREQUAL "x64")
    set(DBGBENCH_ASM src/core/asm_x64.asm)
else()
    set(DBGBENCH_ASM src/core/asm_x86.asm)
endif()

add_executable(debug_bench
    src/main.cpp
    src/core/LiveProbe.cpp
    ${DBGBENCH_ASM}
)
set_target_properties(debug_bench PROPERTIES OUTPUT_NAME "debug-bench")
target_compile_definitions(debug_bench PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
target_link_libraries(debug_bench PRIVATE dbench_core dbench_warnings user32)

# On x86 the linker builds a SAFESEH image, and every object must be marked
# safe. The stub has no exception handlers of its own, so /safeseh marks it
# with an empty handler table. ml64 has no SAFESEH, so this is x86-only.
if(DBGBENCH_ARCH STREQUAL "x32")
    target_compile_options(debug_bench PRIVATE $<$<COMPILE_LANGUAGE:ASM_MASM>:/safeseh>)
endif()

# ---------------------------------------------------------------------------
# The 32-bit executable, from the 64-bit configure.
#
# MSVC's architecture comes from the generator, not a target property, so the
# Win32 binary needs its own configure. This re-runs the same project with
# -A Win32, reusing the Catch2 already fetched so nothing downloads twice.
# ---------------------------------------------------------------------------

if(DBGBENCH_ARCH STREQUAL "x64" AND DBGBENCH_BUILD_X32)
    include(ExternalProject)
    ExternalProject_Add(dbench_x32
        SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
        BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR}/x32-build
        CMAKE_GENERATOR ${CMAKE_GENERATOR}
        CMAKE_GENERATOR_PLATFORM Win32
        CMAKE_ARGS
            -DDBGBENCH_BUILD_TESTS=${DBGBENCH_BUILD_TESTS}
            -DDBGBENCH_BUILD_X32=OFF
            -DDBGBENCH_WARNINGS_AS_ERRORS=${DBGBENCH_WARNINGS_AS_ERRORS}
            -DFETCHCONTENT_SOURCE_DIR_CATCH2=${CMAKE_CURRENT_BINARY_DIR}/_deps/catch2-src
        BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG>
        # ExternalProject stamps its build step on first success and does not
        # know the shared sources changed. Without this the 32-bit binary
        # freezes at its first build while the 64-bit one moves on.
        BUILD_ALWAYS 1
        INSTALL_COMMAND ""
        BUILD_BYPRODUCTS <BINARY_DIR>/$<CONFIG>/debug-bench.exe
    )
    add_dependencies(dbench_x32 debug_bench)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

if(DBGBENCH_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
    if(TARGET dbench_x32)
        # The 32-bit test binary exercises the core with a 32-bit size_t and
        # pointer, the way the 32-bit executable runs it.
        add_test(NAME dbench_tests_x32
                 COMMAND ${CMAKE_CURRENT_BINARY_DIR}/x32-build/tests/$<CONFIG>/dbench_tests.exe)
    endif()
endif()

# ---------------------------------------------------------------------------
# Package: a zip with both executables and the documents.
# ---------------------------------------------------------------------------

install(TARGETS debug_bench RUNTIME DESTINATION release/${DBGBENCH_ARCH})
if(TARGET dbench_x32)
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/x32-build/$<CONFIG>/debug-bench.exe DESTINATION release/x32)
endif()
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
    ${CMAKE_CURRENT_SOURCE_DIR}/README.md
    ${CMAKE_CURRENT_SOURCE_DIR}/CHANGELOG.md
    ${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.md
    DESTINATION DebugBench
)

set(CPACK_PACKAGE_NAME "debug-bench")
set(CPACK_PACKAGE_VENDOR "Game Reversal Club")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "debug-bench-v${PROJECT_VERSION}")
set(CPACK_GENERATOR "ZIP")
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Anti-debug and anti-injection self-test target")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
include(CPack)
