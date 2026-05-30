ethernetip_add_test(test_cip_status
    SOURCES test_cip_status.cpp
    LIBS    ethernetip::cip)

ethernetip_add_test(test_cip_path
    SOURCES test_cip_path.cpp
    LIBS    ethernetip::cip)

ethernetip_add_test(test_encapsulation
    SOURCES test_encapsulation.cpp
    LIBS    ethernetip::cip)

ethernetip_add_test(test_cpf
    SOURCES test_cpf.cpp
    LIBS    ethernetip::cip)

ethernetip_add_test(test_mr_codec
    SOURCES test_mr_codec.cpp
    LIBS    ethernetip::cip)

ethernetip_add_test(test_dispatcher
    SOURCES test_dispatcher.cpp
    LIBS    ethernetip::cip)
