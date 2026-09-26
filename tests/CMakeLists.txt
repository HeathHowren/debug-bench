include(FetchContent)

FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.5.2
    EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(Catch2)

add_executable(dbench_tests
    test_checks.cpp
    test_cli.cpp
    test_report.cpp
)
target_include_directories(dbench_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(dbench_tests PRIVATE dbench_core dbench_warnings Catch2::Catch2WithMain)

list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
include(Catch)
catch_discover_tests(dbench_tests)
