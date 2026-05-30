add_library(ethernetip_connections STATIC
    src/io_connection.cpp
    src/forward_open_request.cpp
    src/connection_path_parser.cpp
    src/connection_manager.cpp
)
add_library(ethernetip::connections ALIAS ethernetip_connections)

target_include_directories(ethernetip_connections PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(ethernetip_connections PUBLIC ethernetip::cip)
target_compile_features(ethernetip_connections PUBLIC cxx_std_20)
