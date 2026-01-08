# libfault

libfault is a lightweight, cross-platform crash reporting and panic library for C++17. It provides a unified interface for saving object traces when things go wrong, whether it's a segmentation fault on Linux, an unhandled exception on Windows, a std::terminate or a manual panic/assertion call in your logic.

## Description

When a C++ application crashes, the default behavior is often a silent exit or a cryptic "Segmentation Fault" message. libfault changes this by intercepting system-level failures and providing developers with the context needed to debug them later, even from production contexts. It abstracts away the platform-specific complexities of POSIX signals and Windows Structured Exception Handling (SEH).

### Key Features
* **Native C & C++ Support:** Use the modern C++ API or the stable C-linkage interface for legacy projects.
* **Unified Crash Handling:** Intercepts SIGSEGV, SIGFPE, SIGILL, and SIGABRT on Linux, and SEH Exceptions on Windows.
* **Async-Signal Safe (AS-Safe):** Prioritizes safe "Object Trace" generation on restrictive environments, or has safeguards for user requested unsafe generation. See below for more info.
* **C++ Terminate Override:** Captures the stack trace of unhandled C++ exceptions before the runtime kills the process.
* **Zero-Config Stack Traces:** Powered by `cpptrace` for high-quality, symbolicated traces.
* **Panic & Assert API:** Provides `fault::panic()`, `DFAULT_ASSERT` and `FAULT_ASSERT` for explicit, fail-fast error handling.
* **Self-Contained:** Can be bundled as a single shared library with no external runtime dependencies for the consumer.
* **User configurability:** Each fault action triggers report writing, user fatal Popups and summary message to terminal. User can switch these on/off independently for abnormal crashes, or user requested panic mode.

---

### Production & Async-Signal Safety

libfault is designed for high-availability production environments where stability during a crash is non-negotiable.

* **Async-Signal Safe (AS-Safe) Collection:** During a fatal signal (Linux) or exception (Windows), the library avoids `malloc`, `free`, and complex C++ runtime calls. It prioritizes collecting signal safe "Raw Object Trace"—a collection of instruction pointers with memory offsets and binary paths, using the `cpptrace` efforts as deriving mechanism.
* **Best-effort Safeguards** If no safe trace can be collected, the user may optionally activate a best-effort approach to collect a regular trace. In this case, the library puts safeguards in place against deadlocks or recursive crashes, to ensure that the program is terminated cleanly, wether the (unsafe) trace is collected or not.
* **Delayed Resolution:** Instead of resolving symbols (function names/filenames) inside the crashed process, libfault outputs a formatted "object trace" in its log.
* **Protected Debug Files:** Developers can resolve these traces locally using their original `.debug` or `.pdb` files. This means your production binaries can remain stripped (small and secure), while your logs remain fully actionable.
* **Trace Resolution is optional** Traces can be optionally resolved for non-restrictive environments, if the user wishes. For safety, this is never done in Linux Posix or Windows SEH environments.

---

## Quick Start

### 1. Integration (CMake FetchContent)
Add this to your `CMakeLists.txt` to integrate libfault directly into your project:

```cmake
include(FetchContent)
FetchContent_Declare(
    fault
    GIT_REPOSITORY [https://github.com/Ridrik/libfault.git](https://github.com/Ridrik/libfault.git)
    GIT_TAG v0.1.0
)
FetchContent_MakeAvailable(fault)

# Link to your application
target_link_libraries(my_app PRIVATE fault::fault)
```


### 2. Basic usage
Initialize the global handlers at the start of your `main()` function.
```
#include <fault/fault.hpp>
#include <iostream>

int main() {
    // Initialize global crash handlers (Signals, SEH, and Terminate)
    if (!fault::init({.appName = "MyApp",
                      .buildID = "MyBuildID",
                      .crashDir = "crash"})) {
        std::cerr << "Failed to initialize libfault.\n";
        return EXIT_FAILURE;
    }

    // Example: Manual Panic
    if (system_in_bad_state) {
        fault::panic("Critical system failure: logic inconsistency detected");
    }

    // Example: Debug Asserts
    DFAULT_ASSERT(data_ptr != nullptr, "Input data pointer is null");

    // Example: access violation
    volatile int* p{nullptr};
    *p = 42;

    return 0;
}
```
---

## 🧩 Third-Party Components and Licenses
faultlib uses `cpptrace` as driving mechanism to collect object traces smoothly across both platforms, and, whenever applicable, signal safe traces. 

| Component | Purpose | License |
| ---------- | -------- | -------- |
| [**cpptrace**](https://github.com/jeremy-rifkin/cpptrace) | Lightweight stack trace and debugging helper | MIT** |

---

## License
`libfault` is licensed under the **MIT License** (see `LICENSE` file).

### Third-Party Dependency Licensing
**`libfault` depends on [cpptrace](https://github.com/jeremy-rifkin/cpptrace). 
* **Standard Build:** MIT.
* **With libdwarf:** If `cpptrace` is configured to use `libdwarf` and is linked **statically**, the resulting binary is subject to the **LGPL** license.

---