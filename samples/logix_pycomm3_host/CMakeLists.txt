add_executable(logix_pycomm3_host main.cpp)
target_link_libraries(logix_pycomm3_host PRIVATE ethernetip::logix ethernetip::protocol)
target_compile_features(logix_pycomm3_host PRIVATE cxx_std_20)
