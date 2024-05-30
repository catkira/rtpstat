#include <cstdint>
#include <vector>

struct Rtp_header {
    uint8_t version;
    bool padding;
    bool extension;
    uint8_t payload_type;
    uint16_t sequence_number;
    uint32_t timestamp;
    uint32_t ssrc;
};

void parse_rtp(std::vector<std::uint8_t> rtp_packet, Rtp_header& rtp_header);