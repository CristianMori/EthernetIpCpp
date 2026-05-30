add_library(ethernetip_cip STATIC
    src/data_serializer.cpp
    src/cip_status.cpp
    src/cip_path.cpp
    src/encapsulation.cpp
    src/cpf.cpp
    src/mr_codec.cpp
    src/cip_attribute.cpp
    src/cip_instance.cpp
    src/cip_service.cpp
    src/standard_services.cpp
    src/cip_class.cpp
    src/cip_dispatcher.cpp
    src/path_builder.cpp
)
add_library(ethernetip::cip ALIAS ethernetip_cip)

target_include_directories(ethernetip_cip PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_features(ethernetip_cip PUBLIC cxx_std_20)
