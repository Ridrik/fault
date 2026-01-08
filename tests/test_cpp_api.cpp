#include <format>
#include <iostream>
#include <stdexcept>

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

int main() {
    // Initialize global crash handlers (Signals, SEH, and Terminate)
    if (!fault::init({.appName = "MyApp", .buildID = "MyBuildID", .crashDir = "crash"})) {
        std::cerr << "Failed to initialize libfault.\n";
        return EXIT_FAILURE;
    }

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