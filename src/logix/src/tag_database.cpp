#include "ethernetip/logix/tag_database.hpp"

#include "ethernetip/logix/logix_data_types.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace ethernetip::logix {

namespace ldt = logix_data_types;

// ---- TemplateDefinition ----

TemplateDefinition::TemplateDefinition(uint16_t instance_id, std::string name,
                                        uint16_t structure_handle, uint32_t structure_size,
                                        std::vector<TemplateMemberInfo> members)
    : instance_id_(instance_id),
      name_(std::move(name)),
      structure_handle_(structure_handle),
      structure_size_(structure_size),
      members_(std::move(members)) {
    // definition_size = (member_count*8 + name_bytes (null-terminated) + padding) / 4 + 6 header words
    int name_bytes = static_cast<int>(name_.size()) + 1;
    for (const auto& m : members_) {
        name_bytes += static_cast<int>(m.name.size()) + 1;
    }
    int total_bytes = static_cast<int>(members_.size()) * 8 + name_bytes;
    total_bytes = (total_bytes + 3) / 4 * 4;
    definition_size_ = static_cast<uint32_t>(total_bytes / 4) + 6;
}

// ---- TagDatabase: tags ----

std::string TagDatabase::lower(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

Tag& TagDatabase::add_tag(std::string name, uint16_t tag_type, int element_count) {
    int element_size = ldt::element_size(tag_type);
    if (element_size < 0) {
        throw std::invalid_argument("Unknown tag type");
    }
    int array_dims = element_count > 1 ? 1 : 0;
    uint16_t symbol_type = ldt::make_atomic_symbol_type(tag_type, array_dims);

    uint32_t id;
    {
        std::scoped_lock lock(mu_);
        id = next_instance_id_++;
    }
    auto tag = std::make_unique<Tag>(id, std::move(name), symbol_type, tag_type,
                                      element_size, element_count);
    return register_tag(std::move(tag));
}

Tag& TagDatabase::add_tag(std::string name, const TemplateDefinition& tmpl, int element_count) {
    int array_dims = element_count > 1 ? 1 : 0;
    uint16_t symbol_type = ldt::make_struct_symbol_type(tmpl.instance_id(), array_dims);
    uint32_t id;
    {
        std::scoped_lock lock(mu_);
        id = next_instance_id_++;
    }
    auto tag = std::make_unique<Tag>(id, std::move(name), symbol_type,
                                      tmpl.structure_handle(),
                                      static_cast<int>(tmpl.structure_size()),
                                      element_count);
    return register_tag(std::move(tag));
}

Tag& TagDatabase::register_tag(std::unique_ptr<Tag> tag) {
    Tag* view = tag.get();
    std::string key = lower(tag->name());
    {
        std::scoped_lock lock(mu_);
        if (by_name_lower_.find(key) != by_name_lower_.end()) {
            throw std::invalid_argument("Tag already exists: " + tag->name());
        }
        by_instance_id_[tag->instance_id()] = view;
        by_name_lower_[std::move(key)] = std::move(tag);
    }
    view->add_value_changed_handler(
        [this](const Tag& t, TagChangeInfo info) { fire_any_tag_changed(t, info); });
    for (auto& h : tag_added_) h(*view);
    return *view;
}

void TagDatabase::fire_any_tag_changed(const Tag& tag, TagChangeInfo info) {
    for (auto& h : any_tag_changed_) h(tag, info);
}

Tag* TagDatabase::find_by_name(std::string_view name) {
    // dotted paths resolve to the root tag
    auto dot = name.find('.');
    std::string_view root = (dot == std::string_view::npos) ? name : name.substr(0, dot);
    std::string key = lower(root);
    std::scoped_lock lock(mu_);
    auto it = by_name_lower_.find(key);
    return it == by_name_lower_.end() ? nullptr : it->second.get();
}

Tag* TagDatabase::find_by_instance_id(uint32_t instance_id) {
    std::scoped_lock lock(mu_);
    auto it = by_instance_id_.find(instance_id);
    return it == by_instance_id_.end() ? nullptr : it->second;
}

std::vector<Tag*> TagDatabase::all_tags() {
    std::scoped_lock lock(mu_);
    std::vector<Tag*> out;
    out.reserve(by_name_lower_.size());
    for (auto& [_, t] : by_name_lower_) out.push_back(t.get());
    return out;
}

int TagDatabase::count() const {
    std::scoped_lock lock(mu_);
    return static_cast<int>(by_name_lower_.size());
}

// ---- TagDatabase: templates ----

int TagDatabase::type_alignment(uint16_t data_type, int element_size) noexcept {
    switch (static_cast<uint16_t>(data_type & 0x00FF)) {
        case 0xC1: return 1;  // BOOL
        case 0xC2: return 1;  // SINT
        case 0xC3: return 2;  // INT
        case 0xC4: return 4;  // DINT
        case 0xC5: return 8;  // LINT
        case 0xCA: return 4;  // REAL
        case 0xCB: return 8;  // LREAL
        case 0xD3: return 4;  // DWORD
        default:   return std::min(element_size, 4);
    }
}

int TagDatabase::align_up(int offset, int alignment) noexcept {
    return (offset + alignment - 1) / alignment * alignment;
}

TemplateDefinition& TagDatabase::add_template(std::string name,
                                                std::vector<TemplateMember> members) {
    uint16_t instance_id;
    {
        std::scoped_lock lock(mu_);
        instance_id = next_template_id_++;
    }

    std::vector<TemplateMemberInfo> resolved;
    resolved.reserve(members.size() + 4);
    int offset = 0;
    int bool_bit_pos = 0;
    int bool_host_offset = -1;
    int bool_host_index = 0;

    for (auto& m : members) {
        bool is_bool_scalar = (m.data_type == ldt::Bool) && (m.array_size == 0);
        if (is_bool_scalar) {
            if (bool_bit_pos == 0 || bool_bit_pos >= 8) {
                bool_host_offset = offset;
                bool_bit_pos = 0;
                std::string host = "ZZZZZZZZZZ" + name + std::to_string(bool_host_index++);
                resolved.push_back(TemplateMemberInfo{
                    std::move(host), ldt::Sint, bool_host_offset, 0, 1});
                offset += 1;
            }
            resolved.push_back(TemplateMemberInfo{
                std::move(m.name), ldt::Bool, bool_host_offset, bool_bit_pos, 0});
            ++bool_bit_pos;
        } else {
            bool_bit_pos = 0;
            bool_host_offset = -1;

            int elem_size = ldt::element_size(m.data_type);
            if (elem_size <= 0) elem_size = 4;

            int alignment = type_alignment(m.data_type, elem_size);
            offset = align_up(offset, alignment);

            int member_size = m.array_size > 0 ? elem_size * m.array_size : elem_size;
            resolved.push_back(TemplateMemberInfo{
                std::move(m.name), m.data_type, offset, m.array_size, elem_size});
            offset += member_size;
        }
    }

    offset = align_up(offset, 4);
    uint16_t struct_handle = static_cast<uint16_t>(0x8000 | instance_id);

    auto def = std::make_unique<TemplateDefinition>(
        instance_id, std::move(name), struct_handle,
        static_cast<uint32_t>(offset), std::move(resolved));
    TemplateDefinition* view = def.get();
    {
        std::scoped_lock lock(mu_);
        templates_[instance_id] = std::move(def);
    }
    for (auto& h : template_added_) h(*view);
    return *view;
}

const TemplateDefinition* TagDatabase::find_template(uint16_t instance_id) const {
    std::scoped_lock lock(mu_);
    auto it = templates_.find(instance_id);
    return it == templates_.end() ? nullptr : it->second.get();
}

std::vector<const TemplateDefinition*> TagDatabase::all_templates() const {
    std::scoped_lock lock(mu_);
    std::vector<const TemplateDefinition*> out;
    out.reserve(templates_.size());
    for (auto& [_, t] : templates_) out.push_back(t.get());
    return out;
}

} // namespace ethernetip::logix
