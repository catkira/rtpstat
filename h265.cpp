#include <stdio.h>

#include "h265.h"

void parse_nal(const std::vector<uint8_t> buf, Nal_header& nal_header)
{
    if (buf.size() < 14) {
        printf("Error: rtp packet is too short, cannot parse H265 header!");
        return;
    }

    const uint16_t tmp = *reinterpret_cast<const uint16_t*>(&buf[12]);
    nal_header.payload_type = (tmp >> 1) & 0x3F;
    nal_header.layer_id = (tmp >> 7) & 0x1F;

    if (nal_header.payload_type == 49) {
        nal_header.start_fu = (buf[14] & 0x80) > 0;
        nal_header.stop_fu = (buf[14] & 0x40) > 0;
        nal_header.fu_type = buf[14] & 0x3F;
    }
}

void get_frame_type(const std::vector<uint8_t> buf, const Nal_header& nal_header, uint8_t& frame_type)
{
    if (nal_header.payload_type == 49) {
        frame_type = buf[15];
    }
    else {
        frame_type = buf[14];
    }
}