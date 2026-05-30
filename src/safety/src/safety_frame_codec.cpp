#include "ethernetip/safety/safety_frame_codec.hpp"

#include "ethernetip/cip/data_serializer.hpp"
#include "ethernetip/safety/safety_crc.hpp"

#include <array>
#include <cstring>
#include <stdexcept>

namespace ethernetip::safety::frame_codec {

namespace ser = ethernetip::cip::serializer;

int wire_size(int data_length, SafetyFormat format) {
    bool is_short = data_length <= 2;
    switch (format) {
        case SafetyFormat::Base:
            return is_short ? data_length + 6 : 2 * data_length + 8;
        case SafetyFormat::Extended:
            // Per CSS k_IO_MSGLEN_SHORT_OVHD = 6 for BOTH base and extended.
            return is_short ? data_length + 6 : 2 * data_length + 8;
    }
    throw std::invalid_argument("invalid SafetyFormat");
}

uint16_t extract_timestamp(std::span<const uint8_t> input, int data_len,
                            SafetyFormat format) {
    bool is_short = data_len <= 2;
    size_t off;
    if (is_short) {
        off = static_cast<size_t>(data_len) + 3;
    } else if (format == SafetyFormat::Base) {
        off = 2u * data_len + 5;
    } else {
        off = 2u * data_len + 6;
    }
    if (off + 2 > input.size()) return 0;
    return ser::read_uint(input.subspan(off));
}

// ---- Base Format Short -----------------------------------------------------

static int encode_base_short(std::span<uint8_t> out, std::span<const uint8_t> data,
                              ModeByte mode, uint16_t ts, uint8_t pid_seed_s1) {
    size_t off = 0;
    std::memcpy(out.data() + off, data.data(), data.size()); off += data.size();
    out[off++] = mode.value();

    // Actual CRC-S1: seed → (mode & 0xE0) → actualData
    uint8_t mask_byte = mode.data_crc_mask();
    uint8_t a_crc = crc::compute_s1(std::span<const uint8_t>(&mask_byte, 1), pid_seed_s1);
    a_crc = crc::compute_s1(data, a_crc);
    out[off++] = a_crc;

    // Complement CRC-S2: seed(S1!) → ((mode^0xFF) & 0xE0) → (data^0xFF)
    uint8_t cmpl_mask = mode.complement_data_crc_mask();
    uint8_t c_crc = crc::compute_s2(std::span<const uint8_t>(&cmpl_mask, 1), pid_seed_s1);
    std::array<uint8_t, 2> comp_buf{};
    for (size_t i = 0; i < data.size(); ++i) comp_buf[i] = static_cast<uint8_t>(data[i] ^ 0xFF);
    c_crc = crc::compute_s2(std::span<const uint8_t>(comp_buf.data(), data.size()), c_crc);
    out[off++] = c_crc;

    // Timestamp + CRC-S1
    ser::write_uint(out.subspan(off), ts); off += 2;
    uint8_t ts_mask = mode.timestamp_crc_mask();
    uint8_t ts_crc = crc::compute_s1(std::span<const uint8_t>(&ts_mask, 1), pid_seed_s1);
    std::array<uint8_t, 2> ts_bytes{};
    ser::write_uint(ts_bytes, ts);
    ts_crc = crc::compute_s1(ts_bytes, ts_crc);
    out[off++] = ts_crc;
    return static_cast<int>(off);
}

static SafetyDecodeResult decode_base_short(std::span<const uint8_t> input, int data_len,
                                              uint8_t pid_seed_s1) {
    if (input.size() < static_cast<size_t>(data_len + 6)) {
        return SafetyDecodeResult::make_error("Input too short for base short frame");
    }
    size_t off = 0;
    std::vector<uint8_t> data(input.begin() + off, input.begin() + off + data_len); off += data_len;
    ModeByte mode{input[off++]};
    uint8_t wire_a = input[off++];
    uint8_t wire_c = input[off++];
    uint16_t ts = ser::read_uint(input.subspan(off)); off += 2;
    uint8_t wire_ts_crc = input[off++];

    uint8_t mask = mode.data_crc_mask();
    uint8_t a_crc = crc::compute_s1(std::span<const uint8_t>(&mask, 1), pid_seed_s1);
    a_crc = crc::compute_s1(data, a_crc);
    if (a_crc != wire_a) return SafetyDecodeResult::make_error("Actual data CRC-S1 mismatch");

    uint8_t cmpl_mask = mode.complement_data_crc_mask();
    uint8_t c_crc = crc::compute_s2(std::span<const uint8_t>(&cmpl_mask, 1), pid_seed_s1);
    std::array<uint8_t, 2> comp_buf{};
    for (int i = 0; i < data_len; ++i) comp_buf[i] = static_cast<uint8_t>(data[i] ^ 0xFF);
    c_crc = crc::compute_s2(std::span<const uint8_t>(comp_buf.data(), data_len), c_crc);
    if (c_crc != wire_c) return SafetyDecodeResult::make_error("Complement data CRC-S2 mismatch");

    uint8_t ts_mask = mode.timestamp_crc_mask();
    uint8_t ts_crc = crc::compute_s1(std::span<const uint8_t>(&ts_mask, 1), pid_seed_s1);
    std::array<uint8_t, 2> ts_bytes{};
    ser::write_uint(ts_bytes, ts);
    ts_crc = crc::compute_s1(ts_bytes, ts_crc);
    if (ts_crc != wire_ts_crc) return SafetyDecodeResult::make_error("Timestamp CRC-S1 mismatch");

    return SafetyDecodeResult{std::move(data), mode, ts, true, std::nullopt};
}

// ---- Base Format Long ------------------------------------------------------

static int encode_base_long(std::span<uint8_t> out, std::span<const uint8_t> data,
                             ModeByte mode, uint16_t ts,
                             uint8_t pid_seed_s1, uint16_t pid_seed_s3) {
    size_t off = 0;
    std::memcpy(out.data() + off, data.data(), data.size()); off += data.size();
    out[off++] = mode.value();

    uint16_t a_crc = crc::compute_s3_byte(mode.data_crc_mask(), pid_seed_s3);
    a_crc = crc::compute_s3(data, a_crc);
    ser::write_uint(out.subspan(off), a_crc); off += 2;

    size_t comp_off = off;
    for (size_t i = 0; i < data.size(); ++i) out[comp_off + i] = static_cast<uint8_t>(data[i] ^ 0xFF);
    auto comp_slice = out.subspan(comp_off, data.size());
    off += data.size();

    uint16_t c_crc = crc::compute_s3_byte(mode.complement_data_crc_mask(), pid_seed_s3);
    c_crc = crc::compute_s3(comp_slice, c_crc);
    ser::write_uint(out.subspan(off), c_crc); off += 2;

    ser::write_uint(out.subspan(off), ts); off += 2;
    uint8_t ts_mask = mode.timestamp_crc_mask();
    uint8_t ts_crc = crc::compute_s1(std::span<const uint8_t>(&ts_mask, 1), pid_seed_s1);
    std::array<uint8_t, 2> ts_bytes{};
    ser::write_uint(ts_bytes, ts);
    ts_crc = crc::compute_s1(ts_bytes, ts_crc);
    out[off++] = ts_crc;
    return static_cast<int>(off);
}

static SafetyDecodeResult decode_base_long(std::span<const uint8_t> input, int data_len,
                                             uint8_t pid_seed_s1, uint16_t pid_seed_s3) {
    if (input.size() < static_cast<size_t>(2 * data_len + 8)) {
        return SafetyDecodeResult::make_error("Input too short for base long frame");
    }
    size_t off = 0;
    std::vector<uint8_t> data(input.begin() + off, input.begin() + off + data_len); off += data_len;
    ModeByte mode{input[off++]};
    uint16_t wire_a = ser::read_uint(input.subspan(off)); off += 2;
    std::vector<uint8_t> comp(input.begin() + off, input.begin() + off + data_len); off += data_len;
    uint16_t wire_c = ser::read_uint(input.subspan(off)); off += 2;
    uint16_t ts = ser::read_uint(input.subspan(off)); off += 2;
    uint8_t wire_ts_crc = input[off++];

    for (int i = 0; i < data_len; ++i) {
        if (static_cast<uint8_t>(data[i] ^ 0xFF) != comp[i]) {
            return SafetyDecodeResult::make_error("Actual vs complement data mismatch");
        }
    }
    uint16_t a_crc = crc::compute_s3_byte(mode.data_crc_mask(), pid_seed_s3);
    a_crc = crc::compute_s3(data, a_crc);
    if (a_crc != wire_a) return SafetyDecodeResult::make_error("Actual data CRC-S3 mismatch");

    uint16_t c_crc = crc::compute_s3_byte(mode.complement_data_crc_mask(), pid_seed_s3);
    c_crc = crc::compute_s3(comp, c_crc);
    if (c_crc != wire_c) return SafetyDecodeResult::make_error("Complement data CRC-S3 mismatch");

    uint8_t ts_mask = mode.timestamp_crc_mask();
    uint8_t ts_crc = crc::compute_s1(std::span<const uint8_t>(&ts_mask, 1), pid_seed_s1);
    std::array<uint8_t, 2> ts_bytes{};
    ser::write_uint(ts_bytes, ts);
    ts_crc = crc::compute_s1(ts_bytes, ts_crc);
    if (ts_crc != wire_ts_crc) return SafetyDecodeResult::make_error("Timestamp CRC-S1 mismatch");

    return SafetyDecodeResult{std::move(data), mode, ts, true, std::nullopt};
}

// ---- Extended Format Short -------------------------------------------------

static int encode_extended_short(std::span<uint8_t> out, std::span<const uint8_t> data,
                                   ModeByte mode, uint16_t ts,
                                   uint32_t pid_seed_s5, uint16_t rollover_count) {
    size_t off = 0;
    std::memcpy(out.data() + off, data.data(), data.size()); off += data.size();
    out[off++] = mode.value();

    uint32_t rc_seed = crc::pid_rollover_seed_s5(rollover_count, pid_seed_s5);

    std::array<uint8_t, 5> crc_in{};  // 1 mode + up to 2 data + 2 ts
    crc_in[0] = mode.data_crc_mask();
    std::memcpy(crc_in.data() + 1, data.data(), data.size());
    ser::write_uint(std::span<uint8_t>(crc_in).subspan(1 + data.size()), ts);
    uint32_t s5 = crc::compute_s5_raw(
        std::span<const uint8_t>(crc_in.data(), 1 + data.size() + 2), rc_seed);

    ser::write_uint(out.subspan(off), static_cast<uint16_t>(s5 & 0xFFFFu)); off += 2;
    ser::write_uint(out.subspan(off), ts); off += 2;
    out[off++] = static_cast<uint8_t>((s5 >> 16) & 0xFFu);
    return static_cast<int>(off);
}

static SafetyDecodeResult decode_extended_short(std::span<const uint8_t> input, int data_len,
                                                  uint32_t pid_seed_s5, uint16_t rollover_count) {
    if (input.size() < static_cast<size_t>(data_len + 6)) {
        return SafetyDecodeResult::make_error("Input too short for extended short frame");
    }
    size_t off = 0;
    std::vector<uint8_t> data(input.begin() + off, input.begin() + off + data_len); off += data_len;
    ModeByte mode{input[off++]};
    uint16_t s5_lo = ser::read_uint(input.subspan(off)); off += 2;
    uint16_t ts    = ser::read_uint(input.subspan(off)); off += 2;
    uint8_t  s5_hi = input[off++];

    uint32_t rc_seed = crc::pid_rollover_seed_s5(rollover_count, pid_seed_s5);
    std::array<uint8_t, 5> crc_in{};
    crc_in[0] = mode.data_crc_mask();
    std::memcpy(crc_in.data() + 1, data.data(), data_len);
    ser::write_uint(std::span<uint8_t>(crc_in).subspan(1 + data_len), ts);
    uint32_t expected_s5 = crc::compute_s5_raw(
        std::span<const uint8_t>(crc_in.data(), 1 + data_len + 2), rc_seed);

    uint32_t wire_s5 = static_cast<uint32_t>(s5_lo) | (static_cast<uint32_t>(s5_hi) << 16);
    if (wire_s5 != (expected_s5 & 0x00FFFFFFu)) {
        return SafetyDecodeResult::make_error("Extended short CRC-S5 mismatch");
    }
    return SafetyDecodeResult{std::move(data), mode, ts, true, std::nullopt};
}

// ---- Extended Format Long --------------------------------------------------

static int encode_extended_long(std::span<uint8_t> out, std::span<const uint8_t> data,
                                  ModeByte mode, uint16_t ts,
                                  uint16_t pid_seed_s3, uint32_t pid_seed_s5,
                                  uint16_t rollover_count) {
    size_t off = 0;
    std::memcpy(out.data() + off, data.data(), data.size()); off += data.size();
    out[off++] = mode.value();

    uint16_t rc_seed_s3 = crc::pid_rollover_seed_s3(rollover_count, pid_seed_s3);
    uint16_t a_crc = crc::compute_s3_byte(mode.data_crc_mask(), rc_seed_s3);
    a_crc = crc::compute_s3(data, a_crc);
    ser::write_uint(out.subspan(off), a_crc); off += 2;

    size_t comp_off = off;
    for (size_t i = 0; i < data.size(); ++i) out[comp_off + i] = static_cast<uint8_t>(data[i] ^ 0xFF);
    auto comp_slice = out.subspan(comp_off, data.size());
    off += data.size();

    uint32_t rc_seed_s5 = crc::pid_rollover_seed_s5(rollover_count, pid_seed_s5);
    std::vector<uint8_t> comp_crc_in(1 + data.size() + 2);
    comp_crc_in[0] = mode.timestamp_crc_mask();   // mode & 0x1F in EF
    std::memcpy(comp_crc_in.data() + 1, comp_slice.data(), data.size());
    ser::write_uint(std::span<uint8_t>(comp_crc_in).subspan(1 + data.size()), ts);
    uint32_t s5 = crc::compute_s5_raw(comp_crc_in, rc_seed_s5);

    ser::write_uint(out.subspan(off), static_cast<uint16_t>(s5 & 0xFFFFu)); off += 2;
    ser::write_uint(out.subspan(off), ts); off += 2;
    out[off++] = static_cast<uint8_t>((s5 >> 16) & 0xFFu);
    return static_cast<int>(off);
}

static SafetyDecodeResult decode_extended_long(std::span<const uint8_t> input, int data_len,
                                                  uint16_t pid_seed_s3, uint32_t pid_seed_s5,
                                                  uint16_t rollover_count) {
    if (input.size() < static_cast<size_t>(2 * data_len + 8)) {
        return SafetyDecodeResult::make_error("Input too short for extended long frame");
    }
    size_t off = 0;
    std::vector<uint8_t> data(input.begin() + off, input.begin() + off + data_len); off += data_len;
    ModeByte mode{input[off++]};
    uint16_t wire_a = ser::read_uint(input.subspan(off)); off += 2;
    std::vector<uint8_t> comp(input.begin() + off, input.begin() + off + data_len); off += data_len;
    uint16_t s5_lo = ser::read_uint(input.subspan(off)); off += 2;
    uint16_t ts    = ser::read_uint(input.subspan(off)); off += 2;
    uint8_t  s5_hi = input[off++];

    for (int i = 0; i < data_len; ++i) {
        if (static_cast<uint8_t>(data[i] ^ 0xFF) != comp[i]) {
            return SafetyDecodeResult::make_error("Actual vs complement data mismatch");
        }
    }

    uint16_t rc_seed_s3 = crc::pid_rollover_seed_s3(rollover_count, pid_seed_s3);
    uint16_t a_crc = crc::compute_s3_byte(mode.data_crc_mask(), rc_seed_s3);
    a_crc = crc::compute_s3(data, a_crc);
    if (a_crc != wire_a) return SafetyDecodeResult::make_error("Actual data CRC-S3 mismatch");

    uint32_t rc_seed_s5 = crc::pid_rollover_seed_s5(rollover_count, pid_seed_s5);
    std::vector<uint8_t> comp_crc_in(1 + data_len + 2);
    comp_crc_in[0] = mode.timestamp_crc_mask();
    std::memcpy(comp_crc_in.data() + 1, comp.data(), data_len);
    ser::write_uint(std::span<uint8_t>(comp_crc_in).subspan(1 + data_len), ts);
    uint32_t expected_s5 = crc::compute_s5_raw(comp_crc_in, rc_seed_s5);

    uint32_t wire_s5 = static_cast<uint32_t>(s5_lo) | (static_cast<uint32_t>(s5_hi) << 16);
    if (wire_s5 != (expected_s5 & 0x00FFFFFFu)) {
        return SafetyDecodeResult::make_error("Complement CRC-S5 mismatch");
    }
    return SafetyDecodeResult{std::move(data), mode, ts, true, std::nullopt};
}

// ---- Dispatch --------------------------------------------------------------

int encode(std::span<uint8_t> output, std::span<const uint8_t> data,
            SafetyFormat format, ModeByte mode, uint16_t ts,
            uint8_t pid_seed_s1, uint16_t pid_seed_s3, uint32_t pid_seed_s5,
            uint16_t rollover_count) {
    bool is_short = data.size() <= 2;
    if (format == SafetyFormat::Base) {
        return is_short
            ? encode_base_short(output, data, mode, ts, pid_seed_s1)
            : encode_base_long (output, data, mode, ts, pid_seed_s1, pid_seed_s3);
    }
    return is_short
        ? encode_extended_short(output, data, mode, ts, pid_seed_s5, rollover_count)
        : encode_extended_long (output, data, mode, ts, pid_seed_s3, pid_seed_s5, rollover_count);
}

SafetyDecodeResult decode(std::span<const uint8_t> input, int data_len,
                            SafetyFormat format,
                            uint8_t pid_seed_s1, uint16_t pid_seed_s3, uint32_t pid_seed_s5,
                            uint16_t rollover_count) {
    bool is_short = data_len <= 2;
    if (format == SafetyFormat::Base) {
        return is_short
            ? decode_base_short(input, data_len, pid_seed_s1)
            : decode_base_long (input, data_len, pid_seed_s1, pid_seed_s3);
    }
    return is_short
        ? decode_extended_short(input, data_len, pid_seed_s5, rollover_count)
        : decode_extended_long (input, data_len, pid_seed_s3, pid_seed_s5, rollover_count);
}

// ---- Time Coordination -----------------------------------------------------

static uint8_t build_ack_byte(uint8_t ping_count_reply) {
    uint8_t ack = static_cast<uint8_t>((ping_count_reply & 0x03) | 0x08);  // bits 1:0 + ping_response bit 3
    int bit_count = 0;
    for (int i = 0; i < 7; ++i) if ((ack >> i) & 1) ++bit_count;
    if (bit_count % 2) ack |= 0x80;
    return ack;
}

int encode_time_coordination(std::span<uint8_t> output,
                              uint8_t ping_count_reply,
                              uint16_t consumer_time_value,
                              uint16_t cid_seed_s3) {
    size_t off = 0;
    uint8_t ack = build_ack_byte(ping_count_reply);
    output[off++] = ack;
    ser::write_uint(output.subspan(off), consumer_time_value); off += 2;
    uint8_t ack2 = static_cast<uint8_t>((((ack ^ 0xFF) & 0x55) | (ack & 0xAA)) & 0xFF);
    output[off++] = ack2;
    uint16_t s3 = crc::compute_s3_byte(ack, cid_seed_s3);
    s3 = crc::compute_s3_u16(consumer_time_value, s3);
    ser::write_uint(output.subspan(off), s3); off += 2;
    return static_cast<int>(off);
}

int encode_time_coordination_extended(std::span<uint8_t> output,
                                       uint8_t ping_count_reply,
                                       uint16_t consumer_time_value,
                                       uint32_t pid_seed_s5) {
    size_t off = 0;
    uint8_t ack = build_ack_byte(ping_count_reply);
    output[off++] = ack;
    ser::write_uint(output.subspan(off), consumer_time_value); off += 2;

    uint32_t s5 = crc::compute_s5_raw(std::span<const uint8_t>(&ack, 1), pid_seed_s5);
    std::array<uint8_t, 2> ts_buf{};
    ser::write_uint(ts_buf, consumer_time_value);
    s5 = crc::compute_s5_raw(ts_buf, s5);

    output[off++] = static_cast<uint8_t>(s5 & 0xFF);
    output[off++] = static_cast<uint8_t>((s5 >> 8) & 0xFF);
    output[off++] = static_cast<uint8_t>((s5 >> 16) & 0xFF);
    return static_cast<int>(off);
}

} // namespace ethernetip::safety::frame_codec
