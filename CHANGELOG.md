## v0.3.0 - January 2026
### Added
- Added explicit integration tests (in progress)
- fault::try_catch: a try/catch wrapper that uses `cpptrace` unwind interceptor, automatically storing traces from exceptions and executing a given `fault` catch policy, namely: calling `fault::panic` (no return); saving a traced exception and signaling for shutdown; or returning with no action. An onException callback is invoked before the policy is enacted, containing the exception pointer, and allowing users to perform any custom actions in it, including retrieving exception types given the `std::exception_ptr`, as well as returning a message that will be displayed for the description of the following `fault::panic` or saved exception trace, if any.
This change allows users to use the full capabilities of `fault` while utilizing the core exception features of `cpptrace`, but in an automatic way such that the consumer does not need to directly refer to `cpptrace`. Example:

```cpp
void foo() {
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
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
    // Example 1 -> execute your software, panicking if an exception triggers (which displays popup, message, and generates report),
    // Automatically logs a trace from exception (thrown context)
    fault::try_catch(foo, fault::CatchPolicy::kPanic);
    // Example 2 -> user provided callback
    fault::try_catch(foo, fault::CatchPolicy::kPanic,
                     [](std::exception_ptr ep, const fault::ObjectTrace& trace) -> std::string {
                         // You may want to analyze what exception was thrown, like you would if
                         // setting up try/catch yourself
                         try {
                             if (ep == nullptr) {
                                 return "";
                             }
                             std::rethrow_exception(ep);
                         } catch (const MyException& e) {
                             log_to_my_file(e.what());
                             return e.what();
                         } catch (const My2ndException& e) {
                             // ....
                         }
                         // etc. etc.
                     });
    // Example 3 -> deferred saving
    // Launch some thread (e.g your simulation)
    std::thread([]() {
        fault::try_catch(foo, fault::CatchPolicy::kSaveExceptionWithShutdownRequest);
    }).detach();
    // Main thread (could be your gui app)
    const auto now = std::chrono::steady_clock::now();
    while (!fault::has_shutdown_request()) {
        // Execute your app logic
    }
    fault::panic_if_has_saved_exception(std::format(
        "Hit after {} milliseconds", std::chrono::duration_cast<std::chrono::milliseconds>(
                                         std::chrono::steady_clock::now() - now)
                                         .count()));
}
```

## v0.2.1 - January 2026
### Updated
- Fixed compilation for MSVC - it should work reliably now.

## v0.2.0 - January 2026
### Added
- API Versioning system - version namespaces (c++), typedef alias (C header). Currently at v1. No actual implementation changes. (**Note**: if new versions are designed, users will have the option to revert to previous versions using FAULT_API_VERSION macro option, that controls which collection defaults to main fault:: namespace or C-based functions & types)

## v0.1.3 - January 2026
### Updated
- Fix related with typo in uptime calculation in fault report & popup
- Code attribute small enhancements
- clang-tidy header & source separation (internal)
- Fixed export attributes on inline header functions

## v0.1.2 - January 2026
### Updated
- Code small enhancements against premature use of library utilities

## v0.1.1 - January 2026
### Added
- std::terminate and panic analysis: `fault` will now log wether terminate or panic was called as a result of an ongoing unwind process (i.e some early code threw but was interrupted before reaching its `catch`)

- Postponed **Exceptions & Traces**. `fault` allows users to save a trace and message for a later shutdown. Example: save exception occured in a thread, signal for shutdown. Then, your main thread can decide to clean critical resources first before panicking. (**Note**) any time a trace is saved, it will be automatically displayed at either `panic`, or even on its std::terminate handler.

## v0.1.0 - January 2026
Initial tag release
### Added
- Linux posix signal handlers, Windows SEH filter and abort handler, std::terminate handler, `panic` function and panic-based assertions.
- Ability to write a report, print summary to stderr, and display a visual popup to alert users.