add_library(ethernetip_device STATIC
    src/assembly_object.cpp
    src/identity_object.cpp
    src/tcpip_interface_object.cpp
    src/ethernet_link_object.cpp
    src/virtual_device.cpp
)
add_library(ethernetip::device ALIAS ethernetip_device)

target_include_directories(ethernetip_device PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(ethernetip_device PUBLIC
    ethernetip::cip
    ethernetip::connections
    ethernetip::protocol)
target_compile_features(ethernetip_device PUBLIC cxx_std_20)
