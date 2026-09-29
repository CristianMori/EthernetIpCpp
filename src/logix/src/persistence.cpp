#include "ethernetip/logix/persistence.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <sstream>
#include <stdexcept>

namespace ethernetip::logix::persistence {

namespace {

constexpr std::array<uint8_t, 4> kMagic = {'E', 'I', 'P', 'S'};
constexpr uint8_t kVersion = 1;

void write_u16(std::ostream& os, uint16_t v) {
    uint8_t b[2] = { static_cast<uint8_t>(v & 0xFF), static_cast<uint8_t>((v >> 8) & 0xFF) };
    os.write(reinterpret_cast<const char*>(b), 2);
}

void write_u32(std::ostream& os, uint32_t v) {
    uint8_t b[4] = {
        static_cast<uint8_t>(v & 0xFF),
        static_cast<uint8_t>((v >> 8) & 0xFF),
        static_cast<uint8_t>((v >> 16) & 0xFF),
        static_cast<uint8_t>((v >> 24) & 0xFF),
    };
    os.write(reinterpret_cast<const char*>(b), 4);
}

void write_string(std::ostream& os, const std::string& s) {
    write_u16(os, static_cast<uint16_t>(s.size()));
    os.write(s.data(), static_cast<std::streamsize>(s.size()));
}

void write_tag(std::ostream& os, const Tag& t) {
    write_string(os, t.name());
    write_u16(os, t.tag_type());
    write_u32(os, static_cast<uint32_t>(t.data_size()));
    auto data = t.get_data();
    os.write(reinterpret_cast<const char*>(data.data()),
             static_cast<std::streamsize>(data.size()));
}

uint16_t read_u16(std::istream& is) {
    uint8_t b[2];
    is.read(reinterpret_cast<char*>(b), 2);
    if (!is) throw std::runtime_error("truncated snapshot");
    return static_cast<uint16_t>(b[0] | (b[1] << 8));
}

uint32_t read_u32(std::istream& is) {
    uint8_t b[4];
    is.read(reinterpret_cast<char*>(b), 4);
    if (!is) throw std::runtime_error("truncated snapshot");
    return static_cast<uint32_t>(b[0])
         | (static_cast<uint32_t>(b[1]) << 8)
         | (static_cast<uint32_t>(b[2]) << 16)
         | (static_cast<uint32_t>(b[3]) << 24);
}

std::string read_string(std::istream& is) {
    uint16_t len = read_u16(is);
    std::string s(len, '\0');
    if (len > 0) {
        is.read(s.data(), len);
        if (!is) throw std::runtime_error("truncated string");
    }
    return s;
}

void skip_tag_record(std::istream& is) {
    (void)read_string(is);
    (void)read_u16(is);
    uint32_t size = read_u32(is);
    std::vector<char> throwaway(size);
    is.read(throwaway.data(), size);
}

void restore_one(std::istream& is, TagDatabase& db,
                 const std::string* program, LoadResult& result) {
    std::string name = read_string(is);
    uint16_t tag_type = read_u16(is);
    uint32_t data_size = read_u32(is);
    std::vector<uint8_t> buffer(data_size);
    is.read(reinterpret_cast<char*>(buffer.data()), data_size);

    Tag* tag = program ? db.find_program_tag(*program, name) : db.find_by_name(name);
    if (tag == nullptr) {
        result.tags_skipped++;
        result.warnings.push_back("Tag '" + name + "' not registered — skipping");
        return;
    }
    if (tag->tag_type() != tag_type) {
        result.tags_skipped++;
        std::ostringstream os;
        os << "Tag '" << name << "' tag_type mismatch (file=0x" << std::hex << tag_type
           << ", current=0x" << tag->tag_type() << ") — skipping";
        result.warnings.push_back(os.str());
        return;
    }
    if (tag->data_size() != static_cast<int>(data_size)) {
        result.tags_skipped++;
        result.warnings.push_back("Tag '" + name + "' data_size mismatch — skipping");
        return;
    }
    tag->set_data_silent(buffer);
    result.tags_restored++;
}

} // namespace

void save(TagDatabase& db, std::ostream& os) {
    os.write(reinterpret_cast<const char*>(kMagic.data()), 4);
    uint8_t hdr[4] = { kVersion, 0, 0, 0 };
    os.write(reinterpret_cast<const char*>(hdr), 4);

    auto controller = db.all_tags();
    std::sort(controller.begin(), controller.end(),
              [](Tag* a, Tag* b) { return a->instance_id() < b->instance_id(); });
    write_u32(os, static_cast<uint32_t>(controller.size()));
    for (Tag* t : controller) write_tag(os, *t);

    auto programs = db.all_programs();
    std::sort(programs.begin(), programs.end(),
              [](ProgramScope* a, ProgramScope* b) { return a->name < b->name; });
    write_u32(os, static_cast<uint32_t>(programs.size()));
    for (ProgramScope* p : programs) {
        write_string(os, p->name);
        std::vector<Tag*> ptags;
        ptags.reserve(p->tags_by_name_lower.size());
        for (auto& [_, up] : p->tags_by_name_lower) ptags.push_back(up.get());
        std::sort(ptags.begin(), ptags.end(),
                  [](Tag* a, Tag* b) { return a->instance_id() < b->instance_id(); });
        write_u32(os, static_cast<uint32_t>(ptags.size()));
        for (Tag* t : ptags) write_tag(os, *t);
    }
}

LoadResult load(TagDatabase& db, std::istream& is) {
    uint8_t header[8];
    is.read(reinterpret_cast<char*>(header), 8);
    if (!is) throw std::runtime_error("truncated snapshot header");
    if (std::memcmp(header, kMagic.data(), 4) != 0) {
        throw std::runtime_error("not a TagDatabase snapshot: bad magic");
    }
    if (header[4] > kVersion) {
        throw std::runtime_error("snapshot version newer than loader");
    }

    LoadResult result;

    uint32_t controller_count = read_u32(is);
    for (uint32_t i = 0; i < controller_count; ++i) {
        restore_one(is, db, nullptr, result);
    }

    uint32_t program_count = read_u32(is);
    for (uint32_t i = 0; i < program_count; ++i) {
        std::string program_name = read_string(is);
        uint32_t tag_count = read_u32(is);
        bool has_program = db.find_program(program_name) != nullptr;
        for (uint32_t j = 0; j < tag_count; ++j) {
            if (has_program) {
                restore_one(is, db, &program_name, result);
            } else {
                skip_tag_record(is);
                result.tags_skipped++;
                result.warnings.push_back("Program '" + program_name + "' not registered — skipping tag records");
            }
        }
    }
    return result;
}

} // namespace ethernetip::logix::persistence
