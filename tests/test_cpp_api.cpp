#include <format>
#include <iostream>
#include <stdexcept>
#include <thread>

#include <cpptrace/cpptrace.hpp>
#include <cpptrace/from_current.hpp>
#include <fault/fault.hpp>

void bar() {
    throw std::logic_error("This shouldn't have happened");
}

void foobar() {
    volatile int* data_ptr{nullptr};
    // Example: Debug only Asserts
    FAULT_ASSERT(data_ptr != nullptr, "Input data pointer is null");
    // Invariant expect, with source location info
    FAULT_EXPECT(data_ptr != nullptr);
    fault::expect(data_ptr != nullptr, "Input data pointer is null");

    // Or, without location info
    fault::verify(data_ptr != nullptr);
}

void terminateTest() {
    cpptrace::try_catch(
        [] {
            struct LaunchThread {
                LaunchThread() : t{[] { std::this_thread::sleep_for(std::chrono::seconds(1)); }} {}

                std::thread t;  // calls std::terminate if in a joinable state
            } a;

            bar();  // throws

            a.t.join();
        },
        [](const std::exception& e) {
            // Deal with it, recover or exit
        });
}

void foo() {
    volatile int* p{nullptr};
    fault::expect_at(p != nullptr);
}

int main() {
    // Initialize global crash handlers (Signals, SEH, and Terminate)
    if (!fault::init({.appName = "MyApp",
                      .buildID = "MyBuildID",
                      .crashDir = "crash",
                      .useUnsafeStacktraceOnSignalFallback = true,
                      .generateMiniDumpWindows = true})) {
        std::cerr << "Failed to initialize libfault.\n";
        return EXIT_FAILURE;
    }

    FAULT_ASSERT(1 > 2);
    foo();

    return 0;
}