#pragma once

#include "ethernetip/logix/tag.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ethernetip::logix {

/// Member spec passed to TagDatabase::add_template — type + name + array size.
struct TemplateMember {
    std::string name;
    uint16_t    data_type = 0;
    int         array_size = 0;   ///< 0 = scalar
};

/// Resolved template member after alignment calculation.
struct TemplateMemberInfo {
    std::string name;
    uint16_t    data_type = 0;
    int         offset = 0;
    int         array_size = 0;   ///< for BOOL members in a struct, this holds bit position
    int         element_size = 0;
};

/// A structure template (UDT) corresponding to a CIP Template Object instance.
class TemplateDefinition {
public:
    TemplateDefinition(uint16_t instance_id, std::string name,
                       uint16_t structure_handle, uint32_t structure_size,
                       std::vector<TemplateMemberInfo> members);

    [[nodiscard]] uint16_t                                instance_id()      const noexcept { return instance_id_; }
    [[nodiscard]] const std::string&                      name()             const noexcept { return name_; }
    [[nodiscard]] uint16_t                                structure_handle() const noexcept { return structure_handle_; }
    [[nodiscard]] uint32_t                                structure_size()   const noexcept { return structure_size_; }
    [[nodiscard]] const std::vector<TemplateMemberInfo>&  members()          const noexcept { return members_; }
    [[nodiscard]] int                                     member_count()     const noexcept { return static_cast<int>(members_.size()); }
    /// Template Object Definition Size in 32-bit words (for Template Read).
    [[nodiscard]] uint32_t                                definition_size()  const noexcept { return definition_size_; }

private:
    uint16_t    instance_id_;
    std::string name_;
    uint16_t    structure_handle_;
    uint32_t    structure_size_;
    std::vector<TemplateMemberInfo> members_;
    uint32_t    definition_size_ = 0;
};

/// In-memory tag database for the Logix simulator. Tags indexed by name
/// (case-insensitive) and by Symbol Object instance ID.
class TagDatabase {
public:
    using TagAddedHandler         = std::function<void(Tag&)>;
    using TemplateAddedHandler    = std::function<void(const TemplateDefinition&)>;
    using AnyTagChangedHandler    = std::function<void(const Tag&, TagChangeInfo)>;

    TagDatabase() = default;
    TagDatabase(const TagDatabase&) = delete;
    TagDatabase& operator=(const TagDatabase&) = delete;

    /// Add an atomic tag. Throws std::invalid_argument on unknown tag type.
    Tag& add_tag(std::string name, uint16_t tag_type, int element_count = 1);

    /// Add a structured tag backed by a template.
    Tag& add_tag(std::string name, const TemplateDefinition& tmpl, int element_count = 1);

    /// Case-insensitive name lookup. Dotted paths (e.g. "MyStruct.member")
    /// resolve to the root tag.
    [[nodiscard]] Tag* find_by_name(std::string_view name);

    [[nodiscard]] Tag* find_by_instance_id(uint32_t instance_id);

    [[nodiscard]] std::vector<Tag*> all_tags();

    [[nodiscard]] int count() const;

    /// Define a structure template (UDT) with Logix alignment + BOOL packing.
    ///
    /// Alignment rules (1756-PM020):
    ///  SINT/BOOL = 1, INT = 2, DINT/REAL/DWORD = 4, LINT/LREAL = 8.
    ///  Structures begin and end on 32-bit boundaries.
    ///
    /// BOOL packing: consecutive BOOLs in a UDT share a hidden host SINT byte
    /// named "ZZZZZZZZZZ<name><n>"; each BOOL records its bit position (0-7)
    /// in the Info field (here: TemplateMemberInfo::array_size for BOOLs).
    TemplateDefinition& add_template(std::string name, std::vector<TemplateMember> members);

    [[nodiscard]] const TemplateDefinition* find_template(uint16_t instance_id) const;

    [[nodiscard]] std::vector<const TemplateDefinition*> all_templates() const;

    void add_tag_added_handler        (TagAddedHandler h)         { tag_added_.push_back(std::move(h)); }
    void add_template_added_handler   (TemplateAddedHandler h)    { template_added_.push_back(std::move(h)); }
    void add_any_tag_changed_handler  (AnyTagChangedHandler h)    { any_tag_changed_.push_back(std::move(h)); }

private:
    Tag& register_tag(std::unique_ptr<Tag> tag);
    void fire_any_tag_changed(const Tag& tag, TagChangeInfo info);

    [[nodiscard]] static std::string lower(std::string_view s);
    [[nodiscard]] static int  type_alignment(uint16_t data_type, int element_size) noexcept;
    [[nodiscard]] static int  align_up(int offset, int alignment) noexcept;

    mutable std::mutex mu_;
    std::unordered_map<std::string, std::unique_ptr<Tag>> by_name_lower_;
    std::unordered_map<uint32_t, Tag*> by_instance_id_;
    uint32_t next_instance_id_ = 1;

    std::unordered_map<uint16_t, std::unique_ptr<TemplateDefinition>> templates_;
    uint16_t next_template_id_ = 0x100;

    std::vector<TagAddedHandler>      tag_added_;
    std::vector<TemplateAddedHandler> template_added_;
    std::vector<AnyTagChangedHandler> any_tag_changed_;
};

} // namespace ethernetip::logix
