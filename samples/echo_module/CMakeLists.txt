add_executable(echo_module main.cpp)
target_link_libraries(echo_module PRIVATE ethernetip::device)
target_compile_features(echo_module PRIVATE cxx_std_20)
