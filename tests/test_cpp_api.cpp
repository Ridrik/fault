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

namespace {

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

int add(int a, int b) {
    return a + b;
}

}  // namespace

void foo() {
    throw std::runtime_error("Shouldn't have happened");
}

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

    try {
        foo();
    } catch (const std::exception& e) {
        fault::panic("Exception caught: {}", e.what());
    }

    // Overriding traces
    cpptrace::try_catch([] { foo(); },
                        [](const std::exception& e) {
                            const auto cppObjectTrace =
                                cpptrace::raw_trace_from_current_exception().resolve_object_trace();
                            const auto objectTrace = fault::adapter::from_cpptrace(cppObjectTrace);
                            fault::panic(objectTrace, "Exception caught: {}", e.what());
                        });

    const auto result = add(5, 2);

    // Assertion: compiles on debug builds by default, with source location
    FAULT_ASSERT(result == 7, "Math is broken");
    FAULT_ASSERT(result == 7, [] { return "math is broken"; });
    FAULT_ASSERT(result == 7, "Math is broken. Got {} instead!", result);
    FAULT_EXPECT_AT(result == 7, "Math is broken. Got {} instead!", result);

    // Expect: Always on, location information by default on debug builds
    fault::expect(result == 7, "Math is broken");
    FAULT_EXPECT(result == 7,
                 "Math is broken");  // Only difference is expr 'result == 7' is also displayed
    // Or, with always source location
    fault::expect_at(result == 7, "Math is broken");

    // Always on, never with source location
    fault::verify(result == 7, "Math is broken");

    // Invariant failures on any of the above produces similar panic action
    const auto c = add(5, 10);
    FAULT_ASSERT(c != 15, "Bad math");

    return 0;
}