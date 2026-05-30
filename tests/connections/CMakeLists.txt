ethernetip_add_test(test_forward_open_parse
    SOURCES test_forward_open_parse.cpp
    LIBS    ethernetip::connections)

ethernetip_add_test(test_connection_path_parser
    SOURCES test_connection_path_parser.cpp
    LIBS    ethernetip::connections)

ethernetip_add_test(test_connection_manager
    SOURCES test_connection_manager.cpp
    LIBS    ethernetip::connections)
