#include <cstdlib>
#include <iostream>

#include <boost/program_options.hpp>
#include <fault/fault.hpp>

#include "fault/core.hpp"

namespace po = boost::program_options;

namespace {

#ifndef CRASH_REPORT_DIR
#define CRASH_REPORT_DIR "crash"
#endif

void infiniteRecursion() {
    std::array<char, 512> buf{};
    infiniteRecursion();
    buf[0] = 0;
}

}  // namespace

int main(int argc, char** argv) {  // NOLINT(bugprone-exception-escape)
    po::options_description desc("Crash options");
    std::string userMsg;
    desc.add_options()("help,h", "Show help")(
        "mode,m", po::value<std::string>()->required(),
        "Crash fault injection type: segfault, overflow, throw, terminate, abort, divzero, panic, "
        "assertion_failure")("message, ms", po::value<std::string>(&userMsg)->default_value(""),
                             "User message for panic and assertions");
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    if (vm.contains("help")) {
        std::cout << desc << "\n";
        return EXIT_SUCCESS;
    }
    po::notify(vm);
    const auto mode = vm["mode"].as<std::string>();

    // Configure fault library
    fault::Config settings{.appName = "test",
                           .buildID = "test_id",
                           .crashDir = CRASH_REPORT_DIR,
                           .reportBaseFileName = "test_report",
                           .showPopUp = false,
                           .panic = fault::Config::PanicSettings{.showPopUp = false}};
    if (!fault::init(settings)) {
        std::cerr << "Couldn't initialize fault\n";
        return EXIT_FAILURE;
    }

    // Trigger crash
    if (mode == "segfault") {
        int* p = nullptr;
        *p = 42;
    }
    if (mode == "overflow") {
        infiniteRecursion();
    }
    if (mode == "throw") {
        throw std::runtime_error("Test exception");
    }
    if (mode == "terminate") {
        std::terminate();
    }
    if (mode == "abort") {
        std::abort();
    }
    if (mode == "divzero") {
        int x = 1 / 0;
        (void)x;
    }
    if (mode == "panic") {
        fault::panic(userMsg);
    }
    if (mode == "assertion_failure") {
        FAULT_ASSERT(0, userMsg);
    }
    if (mode == "try_catch_panic") {
        fault::try_catch([&] { throw std::runtime_error(userMsg); }, fault::CatchPolicy::kPanic);
    }

    std::cerr << "Unknown mode: " << mode << "\n";
    return EXIT_FAILURE;
}
