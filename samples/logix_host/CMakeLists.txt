add_executable(logix_host main.cpp)
target_link_libraries(logix_host PRIVATE ethernetip::logix ethernetip::protocol)
target_compile_features(logix_host PRIVATE cxx_std_20)
