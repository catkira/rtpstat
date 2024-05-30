#include <memory>
#include <atomic>
#include "signal.h"

#include "argparse/argparse.hpp"

#define SPDLOG_FMT_EXTERNAL
#define FMT_HEADER_ONLY
#include "spdlog/spdlog.h"
#include "spdlog/sinks/stdout_color_sinks.h"

std::atomic_bool abort_request = false;

void intHandler(int) {
    abort_request = true;
}

int main(int argc, char* argv[])
{
    argparse::ArgumentParser program("rtpstat", "0.1.0", argparse::default_arguments::help);

    std::shared_ptr<spdlog::logger> logger;

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
        spdlog::register_logger(logger);
    }
    catch (const spdlog::spdlog_ex& ex) {
        std::cout << "Log initialization failed: " << ex.what() << std::endl;
    }

    struct sigaction act;
    act.sa_handler = intHandler;
    sigaction(SIGINT, &act, NULL);

    unsigned int num_rtp_pkts = 0;
    unsigned int num_i_frames = 0;
    unsigned int num_p_frames = 0;

    const auto start_time = std::chrono::high_resolution_clock::now();
    while(!abort_request) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        fmt::print("pkts = {}, I = {}, P = {}\n", num_rtp_pkts, num_i_frames, num_p_frames);
    }

    const auto run_duration = std::chrono::system_clock ::now() - start_time;
    fmt::print("\nstats after {} s:\n", static_cast<float>(std::chrono::duration_cast<std::chrono::milliseconds>(run_duration).count()) / 1000);
    fmt::print("pkts = {}, I = {}, P = {}\n", num_rtp_pkts, num_i_frames, num_p_frames);
    
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