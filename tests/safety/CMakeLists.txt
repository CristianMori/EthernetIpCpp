ethernetip_add_test(test_safety_crc
    SOURCES test_safety_crc.cpp
    LIBS    ethernetip::safety)

ethernetip_add_test(test_safety_types
    SOURCES test_safety_types.cpp
    LIBS    ethernetip::safety)

ethernetip_add_test(test_safety_frame_codec
    SOURCES test_safety_frame_codec.cpp
    LIBS    ethernetip::safety)

ethernetip_add_test(test_safety_segment
    SOURCES test_safety_segment.cpp
    LIBS    ethernetip::safety)

ethernetip_add_test(test_safety_supervisor
    SOURCES test_safety_supervisor.cpp
    LIBS    ethernetip::safety)

ethernetip_add_test(test_safety_validator
    SOURCES test_safety_validator.cpp
    LIBS    ethernetip::safety)

ethernetip_add_test(test_safety_forward_open_builder
    SOURCES test_safety_forward_open_builder.cpp
    LIBS    ethernetip::safety)
