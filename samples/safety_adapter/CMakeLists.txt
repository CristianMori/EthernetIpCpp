add_executable(safety_adapter main.cpp)
target_link_libraries(safety_adapter PRIVATE ethernetip::safety)
target_compile_features(safety_adapter PRIVATE cxx_std_20)
