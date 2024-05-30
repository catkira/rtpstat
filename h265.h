#include <cstdint>
#include <vector>

struct Nal_header {
    //  0: single NAL
    // 48: aggregation packet
    // 49: fragmentation unit
    uint8_t payload_type;
    uint8_t layer_id;
    bool start_fu;
    bool stop_fu;
    uint8_t fu_type;
};

void parse_nal(std::vector<uint8_t> buf, Nal_header& h265_header);