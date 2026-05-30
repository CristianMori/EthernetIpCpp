ethernetip_add_test(test_session_manager
    SOURCES test_session_manager.cpp
    LIBS    ethernetip::protocol)

ethernetip_add_test(test_messages
    SOURCES test_messages.cpp
    LIBS    ethernetip::protocol)

ethernetip_add_test(test_socket_loopback
    SOURCES test_socket_loopback.cpp
    LIBS    ethernetip::protocol)
