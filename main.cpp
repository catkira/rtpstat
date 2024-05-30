#include <memory>
#include <atomic>

#include "signal.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "argparse/argparse.hpp"

#define SPDLOG_FMT_EXTERNAL
#define FMT_HEADER_ONLY
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

#include "rtp.h"
#include "h265.h"

std::shared_ptr<spdlog::logger> logger;
std::atomic_bool abort_request = false;
int sockfd = 0;

void intHandler(int) {
    abort_request = true;
}

void open_socket() {
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        logger->error("ERROR opening socket");
        return;
    }
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    unsigned int portno = 5600;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        logger->error("ERROR on binding");
        return;
    }
}

void close_socket() {

}

int main(int argc, char* argv[])
{
    argparse::ArgumentParser program("rtpstat", "0.1.0", argparse::default_arguments::help);

    program.add_argument("-p", "--port")
        .help("port of rtp stream")
        .nargs(1)
        .scan<'i', int>()
        .default_value(5600);
    program.add_argument("-v", "--verbose")
        .help("verbose console output")
        .implicit_value(true)
        .nargs(0)
        .default_value(false);
    program.add_argument("-vv")
        .help("debug console output")
        .implicit_value(true)
        .nargs(0)
        .default_value(false);

    try {
        program.parse_args(argc, argv);   // Example: ./main --input_files config.yml System.xml
    }
    catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    const bool VERBOSE = (program["-v"] == true);
    const bool VERBOSE_DEBUG = (program["-vv"] == true);

    spdlog::level::level_enum log_level;
    if (VERBOSE)
        log_level = spdlog::level::info;
    else if (VERBOSE_DEBUG)
        log_level = spdlog::level::debug;
    else
        log_level = spdlog::level::err;

    try {
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(log_level);
        logger = std::make_shared<spdlog::logger>("main", console_sink);;
        logger->set_level(log_level);
        spdlog::register_logger(logger);
    }
    catch (const spdlog::spdlog_ex& ex) {
        std::cout << "Log initialization failed: " << ex.what() << std::endl;
    }

    struct sigaction act;
    act.sa_handler = intHandler;
    sigaction(SIGINT, &act, NULL);

    struct sockaddr_in cli_addr;
    socklen_t clilen = sizeof(cli_addr);
    open_socket();

    unsigned int num_rtp_pkts = 0;
    unsigned int num_i_frames = 0;
    unsigned int num_p_frames = 0;
    unsigned int num_b_frames = 0;

    constexpr static unsigned int BUFLEN = 2000;
    std::vector<uint8_t> buf;
    int recv_len = 0;
    bool print_packet_info = true;
    bool wait_FU_end = false;
    bool frame_complete = false;
    uint8_t frame_type = 0;

    Rtp_header rtp_header;
    Nal_header nal_header;
    uint8_t payload_type;

    const auto start_time = std::chrono::high_resolution_clock::now();
    auto last_console_print = std::chrono::high_resolution_clock::now();
    auto frame_start = std::chrono::high_resolution_clock::now();
    while(!abort_request) {
        buf.resize(BUFLEN);
        recv_len = recvfrom(sockfd, reinterpret_cast<char*>(&buf[0]), BUFLEN, MSG_WAITALL, (struct sockaddr *) &cli_addr, &clilen);
        if (recv_len == -1) {
            if (!abort_request)
                logger->error("Error in recvfrom()!");
        }
        else {
            buf.resize(recv_len);
            parse_rtp(buf, rtp_header);
            parse_nal(buf, nal_header);
            if (nal_header.payload_type == 48)
            {
                logger->warn("aggregation packets are currently not supported!",
                    nal_header.payload_type);
            }

            if (print_packet_info) {
                logger->debug("{}: received {} byte packet, type = {}, sequence = {}, timestamp = {}, payload type = {}, layer = {}",
                    num_rtp_pkts, recv_len, rtp_header.payload_type, rtp_header.sequence_number, rtp_header.timestamp,
                    nal_header.payload_type, nal_header.layer_id);
                if (nal_header.payload_type == 49) {
                    logger->debug("fu_start = {}, fu_stop = {}, fu_type = {}", nal_header.start_fu, nal_header.stop_fu, nal_header.fu_type);
                }
            }

            if (nal_header.payload_type == 49) payload_type = nal_header.fu_type;
            else                               payload_type = nal_header.payload_type;

            if (nal_header.payload_type == 49) {
                if (nal_header.start_fu) {
                    if (wait_FU_end) {
                        logger->warn("unexpected start of FU received, end of FU is missing !");
                    }
                    wait_FU_end = true;
                    frame_complete = false;
                    get_frame_type(buf, nal_header, frame_type);
                }
                else if (nal_header.stop_fu) {
                    if (wait_FU_end) wait_FU_end = false;
                    else {
                        logger->warn("unexpected end of FU received !");
                    }
                    frame_complete = true;
                }
                else {
                    frame_complete = false;
                }
            }
            else {
                if (wait_FU_end) {
                    logger->warn("end of FU is missing !");
                }

                frame_complete = true;
                get_frame_type(buf, nal_header, frame_type);
            }

            if (frame_complete && payload_type) {
                if ((payload_type == 21) && (((frame_type >> 2) & 0x07) == 3)) {
                    num_i_frames++;
                    logger->debug("I");
                }
                else if ((payload_type == 1) && (((frame_type >> 3) & 0x07) == 2)) {
                    num_p_frames++;
                    logger->debug("P");
                }
                else if ((payload_type == 1) && (((frame_type >> 6) & 0x01) == 1)) {
                    num_b_frames++;
                    logger->debug("B");
                }
                else if (payload_type == 32) {

                }
                else if (payload_type == 33) {

                }
                else if (payload_type == 34) {

                }
                else if (payload_type == 39) {
                    
                }
                else {
                    logger->info("unknown type: payload type = {}, slice type = {:x}", payload_type, frame_type);
                }
            }
            num_rtp_pkts++;
        }


        if (std::chrono::high_resolution_clock::now() - last_console_print > std::chrono::seconds(1)) {
            fmt::print("pkts = {}, I = {}, P = {}, B = {}\n", num_rtp_pkts, num_i_frames, num_p_frames, num_b_frames);
            last_console_print = std::chrono::high_resolution_clock::now();
        }
    }
    close_socket();

    const auto run_duration = std::chrono::system_clock ::now() - start_time;
    fmt::print("\nstats after {} s:\n", static_cast<float>(std::chrono::duration_cast<std::chrono::milliseconds>(run_duration).count()) / 1000);
    fmt::print("rtp packets = {}, I-frames = {}, P-frames = {}, B-frames = {}\n", num_rtp_pkts, num_i_frames, num_p_frames, num_b_frames);
    
    float i_duration_min = 0;
    float i_duration_max = 0;
    float i_duration_avg = 0;
    float p_duration_min = 0;
    float p_duration_max = 0;
    float p_duration_avg = 0;
    float ip_interval_min = 0;
    float ip_interval_max = 0;
    float ip_interval_avg = 0;
    fmt::print("I duration: avg = {}, min = {}, max = {}\n", i_duration_avg, i_duration_min, i_duration_max);
    fmt::print("P duration: avg = {}, min = {}, max = {}\n", p_duration_avg, p_duration_min, p_duration_max);
    fmt::print("I-P interval: avg = {}, min = {}, max = {}\n", ip_interval_avg, ip_interval_min, ip_interval_max);

    logger->info("done");
    return 0;
}