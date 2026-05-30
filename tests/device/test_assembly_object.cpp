#include "ethernetip/cip/standard_services.hpp"
#include "ethernetip/device/assembly_object.hpp"

#include <atomic>
#include <gtest/gtest.h>

using namespace ethernetip::device;
using namespace ethernetip::cip;

TEST(AssemblyObjectTest, AddInstanceRegistersAttributes) {
    AssemblyObject obj;
    auto& asm_inst = obj.add_instance(100, 8, "test");
    EXPECT_EQ(100u, asm_inst.instance_id());
    EXPECT_EQ(8, asm_inst.data_size());
    auto* cip_inst = obj.cip_class().get_instance(100);
    ASSERT_NE(nullptr, cip_inst);
    EXPECT_NE(nullptr, cip_inst->get_attribute(1));  // # members
    EXPECT_NE(nullptr, cip_inst->get_attribute(3));  // Data
    EXPECT_NE(nullptr, cip_inst->get_attribute(4));  // Size
}

TEST(AssemblyObjectTest, ReadWriteTypedRoundTrip) {
    AssemblyObject obj;
    auto& asm_inst = obj.add_instance(101, 16);
    asm_inst.write<int32_t>(0, -42);
    asm_inst.write<int32_t>(4, 0x12345678);
    EXPECT_EQ(-42, asm_inst.read<int32_t>(0));
    EXPECT_EQ(0x12345678, asm_inst.read<int32_t>(4));
}

TEST(AssemblyObjectTest, DataChangedHandlerFires) {
    AssemblyObject obj;
    auto& asm_inst = obj.add_instance(102, 4);
    std::atomic<int> fired{0};
    asm_inst.add_data_changed_handler(
        [&](uint32_t, std::span<const uint8_t>) { ++fired; });
    asm_inst.set_data(std::vector<uint8_t>{1, 2, 3, 4});
    EXPECT_EQ(1, fired);
    asm_inst.write<uint16_t>(0, 0xBEEF);
    EXPECT_EQ(2, fired);
}

TEST(AssemblyObjectTest, CipGetAttributeReturnsData) {
    AssemblyObject obj;
    auto& asm_inst = obj.add_instance(103, 4);
    asm_inst.set_data(std::vector<uint8_t>{0xDE, 0xAD, 0xBE, 0xEF});

    // Trigger Attribute 3 GET via the standard service handler. The class
    // is moved out of the object below — keep a borrowed reference first.
    auto& cip_class = obj.cip_class();
    CipPath path;
    path.class_id     = AssemblyObject::ClassCode;
    path.instance_id  = 103;
    path.attribute_id = uint16_t{3};

    auto svc = cip_class.get_instance_service(standard_services::GetAttributeSingle);
    ASSERT_NE(nullptr, svc);
    auto resp = svc->handler(*cip_class.get_instance(103),
                              CipServiceRequest{standard_services::GetAttributeSingle,
                                                  path, std::span<const uint8_t>()});
    EXPECT_TRUE(resp.status.is_success());
    ASSERT_EQ(4u, resp.data.size());
    EXPECT_EQ(0xDE, resp.data[0]);
    EXPECT_EQ(0xEF, resp.data[3]);
}
