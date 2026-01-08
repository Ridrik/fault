#include <format>
#include <iostream>
#include <stdexcept>
#include <thread>

#include <cpptrace/cpptrace.hpp>
#include <cpptrace/from_current.hpp>
#include <fault/fault.hpp>

void foo() {
    try {
        throw std::runtime_error("Runtime error");
    } catch (const std::exception& e) {
        fault::panic(std::format("Error in foo: {}", e.what()));
    }
}

void dereferencePtr() {
    volatile int* p{nullptr};
    *p = 42;
}

void bar() {
    throw std::logic_error("This shouldn't have happened");
}

void terminateTest() {
    cpptrace::try_catch(
        [] {
            struct LaunchThread {
                LaunchThread()
                    : t{std::thread([] { std::this_thread::sleep_for(std::chrono::seconds(1)); })} {
                }

                std::thread t;  // calls std::terminate if in a joinable state
            } a;

            bar();  // throws

            a.t.join();
        },
        [](const std::exception& e) {
            // Deal with it, recover or exit
        });
    try {
        struct LaunchThread {
            LaunchThread()
                : t{std::thread([] { std::this_thread::sleep_for(std::chrono::seconds(1)); })} {}

            std::thread t;  // calls std::terminate if in a joinable state
        } a;

        bar();  // throws

        a.t.join();
    } catch (const std::exception& e) {
        // Deal with it, recover or exit
    }
}

int main() {
    // Initialize global crash handlers (Signals, SEH, and Terminate)
    if (!fault::init({.appName = "MyApp",
                      .buildID = "MyBuildID",
                      .crashDir = "crash",
                      .resolveNonSignalTrace = true})) {
        std::cerr << "Failed to initialize libfault.\n";
        return EXIT_FAILURE;
    }

    terminateTest();

    // Segmentation fault
    dereferencePtr();

    // User panic
    foo();

    volatile int* data_ptr{nullptr};
    // Example: Debug only Asserts
    FAULT_ASSERT(data_ptr != nullptr, "Input data pointer is null");
    // Invariant expect, with source location info
    FAULT_EXPECT(data_ptr != nullptr);
    fault::expect(data_ptr != nullptr, "Input data pointer is null");

    // Or, without location info
    fault::verify(data_ptr != nullptr);

    return 0;
}