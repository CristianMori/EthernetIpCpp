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

ethernetip_add_test(test_persistence
    SOURCES test_persistence.cpp
    LIBS    ethernetip::logix)

ethernetip_add_test(test_unsigned_and_bitstring_types
    SOURCES test_unsigned_and_bitstring_types.cpp
    LIBS    ethernetip::logix)

ethernetip_add_test(test_tag_client_unsigned_round_trip
    SOURCES test_tag_client_unsigned_round_trip.cpp
    LIBS    ethernetip::logix ethernetip::device ethernetip::protocol)

ethernetip_add_test(test_logix_structure_handle
    SOURCES test_logix_structure_handle.cpp
    LIBS    ethernetip::logix)
