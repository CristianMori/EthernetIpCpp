add_library(ethernetip_protocol STATIC
    src/socket_compat.cpp
    src/tcp_socket.cpp
    src/udp_socket.cpp
    src/messages.cpp
    src/session_manager.cpp
    src/eip_udp_transport.cpp
    src/eip_adapter.cpp
    src/eip_scanner.cpp
    src/scanner_connection.cpp
    src/connected_explicit.cpp
)
add_library(ethernetip::protocol ALIAS ethernetip_protocol)

target_include_directories(ethernetip_protocol PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(ethernetip_protocol PUBLIC ethernetip::cip ethernetip::connections)
if(WIN32)
    target_link_libraries(ethernetip_protocol PUBLIC ws2_32)
endif()
target_compile_features(ethernetip_protocol PUBLIC cxx_std_20)
