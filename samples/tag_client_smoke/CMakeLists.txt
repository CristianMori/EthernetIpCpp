add_executable(tag_client_smoke main.cpp)
target_link_libraries(tag_client_smoke PRIVATE ethernetip::logix)
target_compile_features(tag_client_smoke PRIVATE cxx_std_20)

add_executable(plc_write_test plc_write_test.cpp)
target_link_libraries(plc_write_test PRIVATE ethernetip::logix)
target_compile_features(plc_write_test PRIVATE cxx_std_20)

add_executable(extensions_smoke extensions_smoke.cpp)
target_link_libraries(extensions_smoke PRIVATE ethernetip::logix)
target_compile_features(extensions_smoke PRIVATE cxx_std_20)

add_executable(plc_multi_read plc_multi_read.cpp)
target_link_libraries(plc_multi_read PRIVATE ethernetip::logix)
target_compile_features(plc_multi_read PRIVATE cxx_std_20)
