add_library(ethernetip_safety STATIC
    src/safety_types.cpp
    src/safety_crc.cpp
    src/safety_network_segment.cpp
    src/safety_frame_codec.cpp
    src/safety_cpcrc.cpp
    src/safety_supervisor_object.cpp
    src/safety_validator_object.cpp
    src/safety_forward_open_builder.cpp
    src/safety_device.cpp
    src/safety_scanner_connection.cpp
)
add_library(ethernetip::safety ALIAS ethernetip_safety)

target_include_directories(ethernetip_safety PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(ethernetip_safety PUBLIC
    ethernetip::cip
    ethernetip::connections
    ethernetip::device
    ethernetip::protocol)
target_compile_features(ethernetip_safety PUBLIC cxx_std_20)
