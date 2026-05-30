add_executable(cip_echo_server main.cpp)
target_link_libraries(cip_echo_server PRIVATE
    ethernetip::protocol
    ethernetip::cip
    ethernetip::connections)
target_compile_features(cip_echo_server PRIVATE cxx_std_20)
