ethernetip_add_test(test_session_manager
    SOURCES test_session_manager.cpp
    LIBS    ethernetip::protocol)

ethernetip_add_test(test_messages
    SOURCES test_messages.cpp
    LIBS    ethernetip::protocol)

ethernetip_add_test(test_socket_loopback
    SOURCES test_socket_loopback.cpp
    LIBS    ethernetip::protocol)

ethernetip_add_test(test_request_timeout
    SOURCES test_request_timeout.cpp
    LIBS    ethernetip::protocol)
target_include_directories(test_request_timeout PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../support)

ethernetip_add_test(test_connect_timeout
    SOURCES test_connect_timeout.cpp
    LIBS    ethernetip::protocol ethernetip::logix)
target_include_directories(test_connect_timeout PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../support)
