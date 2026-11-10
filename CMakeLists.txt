cmake_minimum_required(VERSION 3.20)
project(EthernetIPCpp LANGUAGES CXX VERSION 0.2.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
    # Silence the perennial Winsock-vs-Windows.h ordering noise
    add_compile_definitions(WIN32_LEAN_AND_MEAN NOMINMAX _WINSOCK_DEPRECATED_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

option(ETHERNETIP_BUILD_TESTS    "Build unit and integration tests" ON)
option(ETHERNETIP_BUILD_SAMPLES  "Build runnable example programs"   ON)

# std::thread / std::shared_mutex need the platform thread library on
# glibc < 2.34 (pthread is not yet merged into libc there).
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# ---- Components (each is its own static library) ----
add_subdirectory(src/cip)
add_subdirectory(src/connections)
add_subdirectory(src/device)
add_subdirectory(src/protocol)
add_subdirectory(src/safety)
add_subdirectory(src/logix)

# ---- Tests ----
if(ETHERNETIP_BUILD_TESTS)
    enable_testing()
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.15.2
    )
    # Force googletest to use shared runtime on MSVC (matches our libs)
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    add_subdirectory(tests)
endif()

# ---- Samples ----
if(ETHERNETIP_BUILD_SAMPLES)
    add_subdirectory(samples)
endif()
