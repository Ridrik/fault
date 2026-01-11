# `fault`

`fault` is a lightweight crash reporting and panic library for C and C++, implemented in C++20. It provides a unified interface for capturing object traces and alert users when things go wrong, such as segmentation faults on Linux, unhandled SEH exceptions on Windows, std::terminate, or explicit panics and assertions.

## Description

When a C++ application crashes, the default behavior is often a silent exit or a cryptic "Segmentation Fault" message. `fault` changes this by intercepting system-level failures and providing developers with the context needed to debug them later, even from production contexts. It abstracts away the platform-specific complexities of POSIX signals and Windows Structured Exception Handling (SEH).

### Key Features
* **Native C & C++ Support:** Use the modern C++ API or the stable C-linkage interface for legacy projects.
* **Unified Crash Handling:** Intercepts SIGSEGV, SIGBUS, SIGILL, SIGFPE and SIGABRT on Linux, and main SEH Exception codes on Windows, such as EXCEPTION_STACK_OVERFLOW, EXCEPTION_ACCESS_VIOLATION, divisions by zero, illegal instructions or data misalignments.
* **Async-Signal Safe (AS-Safe):** Prioritizes safe "Object Trace" generation on restrictive environments, or has safeguards for user requested unsafe generation. See below for more info.
* **C++ Terminate Override:** Captures the stack trace of unhandled C++ exceptions before the runtime kills the process.
* **User provided minimal context:** For applications you'd like to distribute to others, `fault` provides users a fatal popup if a critical error occurs, instead of risking a silent and confusing crash.
* **Zero-Config Stack Traces:** Powered by `cpptrace` for high-quality, symbolicated traces.
* **Panic & Assert API:** Provides `fault::panic()`, `fault::expect()`, `fault::expect_at()`, `fault::verify()` and `FAULT_ASSERT` for explicit, fail-fast error handling, including lazy evaluated on-failure actions.
* **Self-Contained:** Can be bundled as a single static or shared library with no external runtime dependencies for the consumer.
* **User configurability:** Each fault action triggers report writing, user fatal Popups and summary message to terminal. User can switch these on/off independently for abnormal crashes, or user requested panic mode.

---

### Production & Async-Signal Safety

`fault` is designed for high-availability production environments where stability during a crash is non-negotiable.

* **Async-Signal Safe (AS-Safe) Collection:** During a fatal signal (Linux) or exception (Windows), the library avoids using the heap or complex C++ runtime calls as much as possible. It prioritizes collecting signal safe "Raw Object Trace", a collection of instruction pointers with memory offsets and binary paths, using the `cpptrace` efforts as deriving mechanism.
* **Best-effort Safeguards** If no safe trace can be collected, the user may optionally activate a best-effort approach to collect a regular trace. In this case, the library puts safeguards in place against deadlocks or recursive crashes, to ensure that the program is terminated cleanly, wether the (unsafe) trace is collected or not. **Note**: currently, on Windows, fully safe object traces can not be generated, and it is recommended for users to allow unsafe generation if a trace is desired. On Linux, safe traces can be collected only when using `libwind` with `_dl_find_object`. By default, `fault` will choose libwind configuration parameter when fetching `cpptrace`. Users may call fault::can_collect_safe_trace() to know wether a safe trace can be collected in restrictive environments.
* **Delayed Resolution:** Instead of resolving symbols (function names/filenames) inside the crashed process, `fault` outputs a formatted "object trace" in its log.
* **Protected Debug Files:** Developers can resolve these traces locally using their original `.debug` or `.pdb` files. This means your production binaries can remain stripped (small and secure), while your logs remain fully actionable.
* **Trace Resolution is optional** Traces can be optionally resolved for non-restrictive environments, if the user wishes. For safety, this is never done in Linux Posix or Windows SEH environments.

---

## Quick Start

### 1. Integration (CMake FetchContent)
Add this to your `CMakeLists.txt` to integrate `fault` directly into your project:

```cmake
include(FetchContent)
FetchContent_Declare(
    fault
    GIT_REPOSITORY [https://github.com/Ridrik/fault.git](https://github.com/Ridrik/fault.git)
    GIT_TAG v0.1.0
)
FetchContent_MakeAvailable(fault)

# Link to your application
target_link_libraries(my_app PRIVATE fault::fault)
```

By default, `fault` is fetched either as dynamic or static library, depending on ${BUILD_SHARED_LIBS}. Users may override it using FAULT_BUILD_SHARED=On/Off (boolean).
(Note: When building from source, cpptrace is fetched as part of it if FAULT_BUNDLE_CPPTRACE=On is selected (default), unless the target already exists. The same configurational options for cpptrace apply)

---

### 2. Basic usage

Initializing `fault` is done by a simple call, taking configuration parameters such as context names, report paths, and settings in what to execute/display in case of program abnormal behaviour.

```cpp

#include <iostream>

#include <fault/fault.hpp> // Or #include <fault/core.hpp> if no <format> options wanted

void foo() {
    volatile int* p{nullptr};
    *p = 42;
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

    foo();

    return 0;
}
```

Will output:

<img src="assets/access_violation_terminal_popup_windows.png" alt="PopUp + terminal message" width="800">

As well as a crash report, containing summaries, timing info and object traces (see below). On Windows, if set, it also generates a minidump to the same directory (.dmp file)

<img src="assets/access_violation_report_windows.png" alt="PopUp + terminal message" width="800">

---

### 3. Multi-thread fault proof

`fault` is resillient to edge cases where multiple threads concurrently perform abnormal operations

```cpp
void foo() {
    volatile int* p{nullptr};
    *p = 42;
}

int main() {
    // Initialize global crash handlers (Signals, SEH, and Terminate)
    if (!fault::init({.appName = "MyApp",
                      .buildID = "MyBuildID",
                      .crashDir = "crash",
                      .useUnsafeStacktraceOnSignalFallback = true,
                      .resolveNonSignalTrace = true,
                      .generateMiniDumpWindows = true})) {
        std::cerr << "Failed to initialize fault.\n";
        return EXIT_FAILURE;
    }

    // Multi threading stress test - only one fault should register consistently
    for (std::uint8_t i{0}; i < 6; ++i) {
        std::thread([i] {
            if (i == 0 || i == 2) {
                foo();
            }
            if (i == 1 || i == 3) {
                std::terminate();
            }
            if (i == 4) {
                std::abort();
            }
            throw std::logic_error("Shouldn't have happened");
        }).detach();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    fault::panic("Some error");

    return 0;
}
```
Will produce consistent behaviour, only registering the 1st fault to enter any handler

<img src="assets/multi_thread_stress_linux.png" alt="Multi-thread stress proof" width="800">

---

## 4. Integrates well with cpptrace

`fault` uses `cpptrace` to produce smooth cross-platform traces. This also includes the ability to recover trace from exceptions at the throw site. Note the following example:

```cpp
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

int main() {
    // Initialize global crash handlers (Signals, SEH, and Terminate)
    if (!fault::init({.appName = "MyApp",
                      .buildID = "MyBuildID",
                      .crashDir = "crash",
                      .resolveNonSignalTrace = true})) {
        std::cerr << "Failed to initialize fault.\n";
        return EXIT_FAILURE;
    }

    terminateTest();

    return 0;
}
```

The user has a cpptrace::try_catch installed, and is explicitly joining the std::thread created. However, during execution, some function throws. Before reaching the `catch`, `LaunchThread` destructor runs, which sees std::thread in a joinable state and calls std::terminate. With normal object tracing, the user would have no idea (directly) that it was bar() that threw. By combining traces from exceptions in `fault` terminate handler, one can reach:

<img src="assets/crash_report_terminate_with_cpptrace_linux.png" alt="Crash report with cpptrace" width="800">

A fake frame is put in the middle, labelled "====== UPSTREAM ======" for user visibility. Now, the user will know not only what triggered the terminate (the joinable thread), but where the initial fault was.

---

### 5. Panic, Assertions, Expectations

`fault` also allows users to explicitly abort the program with similar actions and reports as the signal/termination handlers. Namely, the user may:

1. **panic** panic may be called at any point to display terminal message, user popup, reports and dumps, before aborting the program.
2. **FAULT_ASSERT** fault assert is an assertion macro that checks for invariants, and panics if the assertion fails, displaying location information. By default, it only compiles in debug builds, but may be overriden by using `FAULT_ASSERTIONS=ON/OFF/DEFAULT` (as strings)
3. **fault::expect**, **fault::expect_at**, **FAULT_EXPECT**, **FAULT_EXPECT_AT**. Similar to assertions, it performs invariant checks, panicking if failing. However, these are present also in release builds. **fault::expect_at** always displays location information (line, function, file), whereas, by default, **fault::expect** hides them on non-debug builds. Users may override `fault::expect` location memory by using `FAULT_LOCATIONS=ON/OFF/DEFAULT` (as strings)
4. **fault::verify**. Similar to the above, but it is present in any build type, and will never show location information.

Example:

```cpp
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

    Context context;

    const auto result = add(5, 2);

    // Assertion: compiles on debug builds by default, with source location
    FAULT_ASSERT(result == 7, "Math is broken");

    // Expect: Always on, location information by default on debug builds
    fault::expect(result == 7, "Math is broken");
    
    // Each invariant check has a callable version for lazy evaluation
    fault::expect(result == 7, [&] {
        return std::format(
            "This is a large formatted string on the heap that prints a complex context struct {}. This callable "
            "provides lazy evaluation (only formats string on failure) and allows for follow up actions, if desired",
            context.to_string())
    });

    FAULT_EXPECT(result == 7,
                 "Math is broken");  // Only difference is expr 'result == 7' is also displayed
    // Or, with always source location
    fault::expect_at(result == 7, "Math is broken");

    // Always on, never with source location
    fault::verify(result == 7, "Math is broken");
    // verify, expect, expect_at and its macros (including FAULT_ASSERT) have overloads or versions for format strings
    fault::verify(result == 7, "Math is broken. Result is {}", result);
    fault::verify(result == 7, [&] { const auto res = getSomeContext(); return res.print(); });
    FAULT_VERIFY(result == 7);

    // Invariant failures on any of the above produces similar panic action
    const auto c = add(5, 10);
    FAULT_ASSERT(c != 15, "Bad math");

    return 0;
}
```

On debug build will abort with:

<img src="assets/assert_failure_display_windows.png" alt="Assertion failure display" width="800">


**Note** On Linux, if reraise signal is set, all these panic/assertions will end with reraising default SIGABRT, which usually prints the default abort message with core dumped (if system configured). On Windows, Minidump is instead explicitly generated if set on configuration, and afterwards the program is terminated. This follows the same final step as std::terminate handling.

**Note** All panic and assertions have overloads with invokable functions for deferred evaluation. In addition, there are also overloads or versions available for with formatted args, as long as the user includes `fault/format.hpp` or the general `fault/fault.hpp`. It is overloaded for `fault::verify`, `fault::expect` and `fault::expect_at`. Users may also choose the macro versions `FAULT_EXPECT_FMT` and `FAULT_EXPECT_AT_FMT`. For **`fault::panic`**, `fault::panic_fmt` is available to format strings.

# Panic

**`fault::panic`** (or C's **`fault_panic`**) may be called explicitly by the user to perform a controlled program abort. It takes a user message string view, as well as an optional provided object trace. For instance, users may find it an useful feature after having caught a thrown exception in which the program needs to be aborted. `fault` makes it so that, whichever fault your program suffered, you get a saved trace report to resolve later, and your application users get a fatal popup instead of a silent crash. (**Note** that popups can be turned off in case the application is headless mode or when it must be restarted immediately)

```cpp
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

    cpptrace::try_catch([] { foo(); },
                        [](const std::exception& e) {
                            const auto objectTrace =
                                cpptrace::raw_trace_from_current_exception().resolve_object_trace();

                            fault::panic(e.what(), fault::adapter::from_cpptrace(objectTrace));
                            // If no override trace is desired, version with format args also exists:
                            // fault::panic_fmt("Caught following exception: {}", e.what());
                        });
}

```


---

### 6. Utilities

`fault` provides the following utilities:

1. Shutdown requests: if set, it registers SIGINT and SIGTERM to set shutdown requests. This allows users to check, on their code, whenever a termination request has come by simply calling **fault::has_shutdown_request** (`fault_has_shutdown_request` for C users). Users may also set themselves a shutdown request by calling **fault::set_shutdown_request** (`fault_set_shutdown_request` for C users), useful for multi-threaded applications.
2. **Symbol resolver** script, which can be found in `scripts/symbol_resolver.py`. It can resolve an object trace of the crash report given original .debug files in a subdirectory tree that can be mapped via the BUILD ID that the user gave to `fault` configuration. Alternately, if the fault happened on the same machine as the script, it can take directly the object paths reported in it.
Example: `python scripts/symbol_resolver.py --use_same_paths=1 path/to/crash_report.log`. **Note** it uses addr2line to resolve the trace. Feel free to customize it to your needs.

---

### 7. `fault` in C

`fault` works for C consumers, thanks to its `fault.h` API header. The behaviour largely mimics the one in C++, with the obvious exception of having no std::terminate handling.

```c
void infinite_recursion() {
    volatile char buffer[256];
    infinite_recursion();
    buffer[0] = 0;
}

int main() {
    FaultConfig config = fault_get_default_config();
    config.appName = "MyApp";
    config.buildID = "MyBuildID";
    config.crashDir = "crash";
    config.useUnsafeStacktraceOnSignalFallback = true;
    const FaultInitResult res =
        fault_init(&config);  // if no config changes wanted, user can call fault_init(NULL)
    if (!res.success) {
        printf("Failed to init fault\n");
        return 1;
    }

    infinite_recursion();  // Triggers seg fault on linux & stack overflow on windows

    // Example with callable for deferred evaluation (no source location, always on)
    int status = 404;
    fault_verify_c(status == 200, on_panic, &status);

    printf("C API test passed\n");
    return 0;
}
```

`fault` reserves stack on both platforms to ensure stack overflows are properly displayed.

<img src="assets/overflow_linux_c.png" alt="Overflow display in C (Linux)" width="800">

With crash report:

<img src="assets/overflow_report_linux_c.png" alt="Overflow report in C (Linux)" width="800">

(...continues)

Other macros/functions available: **FAULT_ASSERT** (default for debug, always with source location), **FAULT_EXPECT**, **FAULT_EXPECT_AT** (always on, by default `EXPECT` has source location on debug builds only), **FAULT_VERIFY**. All these macros have a macro version with suffix "_C", standing for callbacks. Examples:

**Note** For C++ users that want callback options: while you can use these versions reliably, it is recommended to use the embedded overloads in `fault::<function_name>` (which invokes any callable).

```c
const char* on_panic(void* data) {
    int* val = (int*)data;
    if (*val == 404) {
        return "Resource not found";
    }
    return "Unknown system failure";
}

int main() {
    FaultConfig config = fault_get_default_config();
    config.appName = "MyApp";
    config.buildID = "MyBuildID";
    config.crashDir = "crash";
    config.useUnsafeStacktraceOnSignalFallback = true;
    const FaultInitResult res =
        fault_init(&config);  // if no config changes wanted, user can call fault_init(NULL)
    if (!res.success) {
        printf("Failed to init fault\n");
        return 1;
    }
    int status = 404;
    FAULT_VERIFY_C(status == 200, on_panic, &status);
    FAULT_EXPECT_C(status == 200, on_panic, &status);
    FAULT_EXPECT_AT_C(status == 200, on_panic, &status);
    fault_verify_c(status == 200, on_panic, &status);

    printf("C API test passed\n");
    return 0;
}
```

---
## Headers

Fault uses a main, core, header, alongside optional ones that extend functionality (as well as dependencies). A short summary of the public headers is seen below:

| Header | Purpose | Notes |
| ---------- | -------- | -------- |
| fault/core.hpp | core functionality, including initialization, panic & assertion, utilities | Suitable for most c++ consumers when not using format-based arguments or cpptrace adapter |
| fault/format.hpp | overloads or versions for panic and assertion functions & macros | Needed for std::format based strings |
| fault/fault.hpp | Everything accessible from `fault` C++ headers, minus the adapter | Recommended to use if you don't mind the `<format>` header |
| fault/adapter/stacktrace.hpp | Simple header-only conversion between `cpptrace` and `fault` | Ensures that consumers do not need to depend directly on `cpptrace` unless override traces are desired |
| fault/fault.h | Header for C consumers | If this library is pre-compiled, and you are using an older C++ version than C++20, then you may also use this |

---

## Author's Note

The goal of this library is to provide safeguards that work reliably against all common software faults, without the need of complex tools or dependencies. `fault` achieves a smooth, thread-safe, default-async-signal-safe operations and, when needed (or by redundancy), safeguards against unsafe trace generation. Apart from this, `fault` also warns the user with basic fatal popups instead of silent crashes, which you may find useful wether when debugging or for end users.

Another goal of `fault` is to be non-intrusive in saving a trace. It does not try to resolve symbols by default, making it useful for production scenarios where, in case of a fault, the user/client can simply send the reports for you to resolve locally given your debug files.

Lastly, `fault` provides a modern framework for `panic` based commands and assertions, which is backed up by `fault`'s overall handling. Users may find interesting as replacement for macros whenever applicable, as well as having invocable and format-based options, wether function-based or macro-based.

---

## 🧩 Third-Party Components and Licenses
`fault` uses `cpptrace` as driving mechanism to collect object traces smoothly across both platforms, and, whenever applicable, signal safe traces. 

| Component | Purpose | License |
| ---------- | -------- | -------- |
| [**cpptrace**](https://github.com/jeremy-rifkin/cpptrace) | Lightweight stack trace and debugging helper | MIT** |

---

## License
`fault` is licensed under the **MIT License** (see `LICENSE` file).

**`fault` depends on [cpptrace](https://github.com/jeremy-rifkin/cpptrace). 
* **Standard Build:** MIT.
* **With libdwarf:** If `cpptrace` is configured to use `libdwarf` and is linked **statically**, the resulting binary is subject to the **LGPL** license. Linking this condition statically to `fault` will therefore make the resulting binary LGPL.

---