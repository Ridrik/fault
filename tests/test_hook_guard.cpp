#include <exception>
#include <iostream>
#include <stdexcept>
#include <thread>

// clang-format off
#include <fault/adapter/stacktrace.hpp>
#include <fault/fault.hpp>
// clang-format on

#include <cpptrace/basic.hpp>
#include <cpptrace/cpptrace.hpp>
#include <cpptrace/from_current.hpp>

#include "fault/core.hpp"

namespace {

void processFile() {
    throw std::runtime_error("Failed to open file!");
}

void bar() {
    fault::UnwindGuardAt hook{[] -> std::string { return "Entered bar..."; }};

    FAULT_DEBUG_FAIL([] -> std::string { return "Calling processFile..."; });
    processFile();
}

void foo() {
    fault::FailGuardAt guard{[]() -> std::string { return "Fail guard, with location"; },
                             fault::HookScope::kThreadLocal};
    fault::UnwindGuardAt guard2{[]() -> std::string { return "Unwind guard, with location"; }};
    fault::PanicGuard hook{[] -> std::string { return "Calling bar..."; },
                           fault::HookScope::kGlobal};
    bar();
}

}  // namespace

int main() {
    // Initialize global crash handlers (Signals, SEH, and Terminate)
    if (!fault::init({.appName = "MyApp",
                      .buildID = "MyBuildID",
                      .crashDir = "crash",
                      .useUnsafeStacktraceOnSignalFallback = true,
                      .generateMiniDumpWindows = true})) {
        std::cerr << "Failed to initialize fault.\n";
        return EXIT_FAILURE;
    }
    fault::FailGuardAt hook{[] -> std::string { return "Fault guard with location"; },
                            fault::HookScope::kGlobal};
    FAULT_DEBUG_GUARD_AT([]() -> std::string { return "Entering try/catch"; });
    try {
        fault::FailGuardAt guard{[]() -> std::string { return "Calling foo..."; }};
        foo();
    } catch (const std::exception& e) {
        fault::panic("Caught exception: {}", e.what());
    }

    return 0;
}