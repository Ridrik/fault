#include <chrono>
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

int add(int a, int b) {
    return a + b;
}

void bar() {
    fault::PanicGuard hook{[] { return "First 2 additions"; }, fault::HookScope::kThreadLocal};

    const auto res = add(5, 10);
    FAULT_ASSERT(res > 0, "{} with {} Should be positive", 5, 10);

    const auto res2 = add(1, 2);
    FAULT_ASSERT(res2 == res, "{} not the same as res2 {}", res, res2);
}

void foo() {
    fault::PanicGuard hook{[] { return "Adding some numbers that must stay coherent"; },
                           fault::HookScope::kGlobal};
    std::thread([] { bar(); }).detach();
    std::this_thread::sleep_for(std::chrono::seconds(2));
    fault::panic("Shouldn't have happened!");
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

    fault::PanicGuard hook{[] { return "Print some general, app-wise context"; },
                           fault::HookScope::kGlobal};
    foo();

    return 0;
}