add_library(ethernetip_logix STATIC
    src/tag_database.cpp
    src/tag_services.cpp
    src/symbol_object.cpp
    src/template_object.cpp
    src/multi_service_handler.cpp
    src/logix_dispatcher.cpp
    src/tag_client.cpp
)
add_library(ethernetip::logix ALIAS ethernetip_logix)

target_include_directories(ethernetip_logix PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_link_libraries(ethernetip_logix PUBLIC
    ethernetip::device
    ethernetip::connections
    ethernetip::protocol
)
target_compile_features(ethernetip_logix PUBLIC cxx_std_20)
