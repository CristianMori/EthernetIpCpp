ethernetip_add_test(test_tag_database
    SOURCES test_tag_database.cpp
    LIBS    ethernetip::logix)

ethernetip_add_test(test_tag_services
    SOURCES test_tag_services.cpp
    LIBS    ethernetip::logix)

ethernetip_add_test(test_logix_dispatcher
    SOURCES test_logix_dispatcher.cpp
    LIBS    ethernetip::logix)

ethernetip_add_test(test_walker
    SOURCES test_walker.cpp
    LIBS    ethernetip::logix)

ethernetip_add_test(test_walker_dispatch
    SOURCES test_walker_dispatch.cpp
    LIBS    ethernetip::logix)
