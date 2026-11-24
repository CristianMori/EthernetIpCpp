cmake_minimum_required(VERSION 3.20)
project(EthernetIPCpp LANGUAGES CXX VERSION 0.3.3)

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

# Install rules and the exported EthernetIPCpp package. On by default for a
# top-level build; off when this project is pulled in with add_subdirectory /
# FetchContent so the host project's own `cmake --install` does not silently
# gain our headers and archives.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(_ethernetip_install_default ON)
else()
    set(_ethernetip_install_default OFF)
endif()
option(ETHERNETIP_INSTALL "Generate install rules and the EthernetIPCpp CMake package"
       ${_ethernetip_install_default})

include(GNUInstallDirs)

# Installs one library target and its public headers, and adds it to the
# export set. Target ethernetip_cip is exported as ethernetip::cip, matching
# the in-tree ALIAS targets, so the same name works for FetchContent and
# find_package consumers.
function(ethernetip_install_component target)
    if(NOT ETHERNETIP_INSTALL)
        return()
    endif()
    string(REPLACE "ethernetip_" "" _component "${target}")
    # DEBUG_POSTFIX keeps Debug and Release archives distinct in one prefix
    # (ethernetip_cip.lib vs ethernetip_cipd.lib). Without it the second
    # `cmake --install` overwrites the first, and on MSVC a Debug consumer
    # then fails with LNK2038 against the Release library. Set here, after the
    # ETHERNETIP_INSTALL guard, so FetchContent/add_subdirectory builds keep
    # their plain output names.
    set_target_properties(${target} PROPERTIES EXPORT_NAME ${_component}
                                               DEBUG_POSTFIX d)
    install(TARGETS ${target}
        EXPORT EthernetIPCppTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.hpp")
endfunction()

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

# ---- Install / package export ----
if(ETHERNETIP_INSTALL)
    include(CMakePackageConfigHelpers)
    set(ETHERNETIP_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/EthernetIPCpp)

    install(EXPORT EthernetIPCppTargets
        FILE EthernetIPCppTargets.cmake
        NAMESPACE ethernetip::
        DESTINATION ${ETHERNETIP_INSTALL_CMAKEDIR})

    configure_package_config_file(
        cmake/EthernetIPCppConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/EthernetIPCppConfig.cmake
        INSTALL_DESTINATION ${ETHERNETIP_INSTALL_CMAKEDIR})

    # Pre-1.0: a minor bump may break the API, so only the same minor matches.
    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/EthernetIPCppConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMinorVersion)

    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/EthernetIPCppConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/EthernetIPCppConfigVersion.cmake
        DESTINATION ${ETHERNETIP_INSTALL_CMAKEDIR})
endif()

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
    # Keep GoogleTest out of our install tree and package export.
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    add_subdirectory(tests)
endif()

# ---- Samples ----
if(ETHERNETIP_BUILD_SAMPLES)
    add_subdirectory(samples)
endif()
