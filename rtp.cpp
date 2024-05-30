#include "rtp.h"
#include <stdio.h>

void parse_rtp(std::vector<std::uint8_t> rtp_packet, Rtp_header& rtp_header)
{
    if (rtp_packet.size() < 12) {
        printf("Error: rtp packet is too short, cannot parse RTP header!");
        return;
    }
    
    rtp_header.version = rtp_packet[0] & 0x03;
    rtp_header.padding = (rtp_packet[0] & 0x04) != 0;
    rtp_header.payload_type = rtp_packet[0] >> 1;
    rtp_header.sequence_number = *reinterpret_cast<uint16_t*>(&rtp_packet[2]);
    rtp_header.timestamp = *reinterpret_cast<uint32_t*>(&rtp_packet[4]);
    rtp_header.ssrc = *reinterpret_cast<uint32_t*>(&rtp_packet[8]);
}