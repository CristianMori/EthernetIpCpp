ethernetip_add_test(test_assembly_object
    SOURCES test_assembly_object.cpp
    LIBS    ethernetip::device)

ethernetip_add_test(test_virtual_device_loopback
    SOURCES test_virtual_device_loopback.cpp
    LIBS    ethernetip::device)
