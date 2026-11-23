# Standalone consumer of an installed EthernetIPCpp. Not part of the main
# build; run it against an install prefix:
#
#   cmake --install build --prefix /tmp/eip
#   cmake -S tests/package -B build-pkg -DCMAKE_PREFIX_PATH=/tmp/eip
#   cmake --build build-pkg && ctest --test-dir build-pkg
cmake_minimum_required(VERSION 3.20)
project(EthernetIPCppPackageTest LANGUAGES CXX)

find_package(EthernetIPCpp 0.3 CONFIG REQUIRED)

enable_testing()
add_executable(package_consumer main.cpp)
target_link_libraries(package_consumer PRIVATE
    ethernetip::protocol ethernetip::logix ethernetip::safety)
add_test(NAME package_consumer COMMAND package_consumer)
