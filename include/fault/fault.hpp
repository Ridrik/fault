/*

FaultLib - A C++ and C fault handling library, containing signal and exception handlers, as well as
user assertions and panic options, generating reports with metadata, raw or resolved traces, and
more

Developer: Rodrigo Rosa
License: MIT 2026

Linux Signal Handling:
    Searches for `zenity` and `kdialog` on `$PATH`, recording their locations, if any.
    sets signal handlers for: SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT. Each handler
    does the following if triggered: 1. Generate and write object trace to crash report
    directory, 2. prints summary error message on stderr, 3. Displays user popup if available
    (trying zenity, then kdialog). 4. If set, reraises default signal, else exits with no further
    cleanup. User popup are implemented using either `zenity` or `kdialog`, which requires them to
    be found in `$PATH`.

Windows Exception Handling:
    sets signal handler for SIGABRT and sets an unhandled exception filter. The following codes are
    intercepted: EXCEPTION_STACK_OVERFLOW, EXCEPTION_ACCESS_VIOLATION,
    EXCEPTION_ILLEGAL_INSTRUCTION, EXCEPTION_IN_PAGE_ERROR, EXCEPTION_ARRAY_BOUNDS_EXCEEDED,
    EXCEPTION_DATATYPE_MISALIGNMENT, EXCEPTION_INT_DIVIDE_BY_ZERO, EXCEPTION_FLT_DIVIDE_BY_ZERO,
    EXCEPTION_ILLEGAL_INSTRUCTION, and EXCEPTION_PRIV_INSTRUCTION. Both for these codes and for
    Abort signal, the following steps are made:
    1. Generate and write object trace to crash report directory (see setCrashWriteDir); 2. Writes
    summary error message to stderr (if enabled) 3. Displays user popup with termination status;
    4. Returns from Windows Handler with execute handler comand, or Terminates Process if on abort
    handler

Both platforms Signal/Exception handling
    @Note Thread-safe
    @Note Signal safety is prioritized, noting that safe trace generation is only available on
    certain configurations. User may choose to set a config flag to collect a regular (signal
    unsafe) trace as fallback, to which the report will become a best-effort attempt. This library
    attempts to mitigate this action with deadlock expiration safeguards, so that the expected
    termination behaviour is seen nonetheless.

Terminate Handling
    Sets std::terminate handler. Performs the following, depending on init config flags: Creates
    object trace and message with unhandled exception; runs user hook; writes the crash report,
    prints summary message to stderr, and displays user popup, followed by terminating process with
    SIGABRT code on Linux, and code 3 on Windows

    @Note On Linux, popup is dependent on either zenity or kdialog being found on `$PATH`
*/

#ifndef FAULT_HPP
#define FAULT_HPP

#include "fault/fault_export.h"

#include <cstdint>
#include <optional>
#include <source_location>
#include <string>
#include <string_view>
#include <vector>

namespace fault {

constexpr std::string_view kDefaultErrorMessage{
    "The application encountered a fatal error and must close. If the problem "
    "persists, please "
    "contact the program maintainer."};

struct FAULT_EXPORT Frame {
    std::uintptr_t rawAddress;
    std::uintptr_t objAddress;
    std::string objPath;
};

struct FAULT_EXPORT ObjectTrace {
    std::vector<Frame> frames;
};

using TerminateHook = void (*)(std::string& userMessage, ObjectTrace& objectTrace);

enum class ConfigWarning : std::uint8_t {
    kNone = 0,
    kAlreadyInitialized = 1 << 0,
    kBaseErrMsgTruncated = 1 << 1,
    kReportPathTooLong = 1 << 2,
    kReportPathWriteTestFailed = 1 << 3,
    kInternalError = 1 << 4
};

constexpr ConfigWarning operator|(ConfigWarning a, ConfigWarning b) {
    return static_cast<ConfigWarning>(static_cast<std::uint8_t>(a) | static_cast<std::uint8_t>(b));
}

struct FAULT_EXPORT Config {
    struct TerminateSettings {
        bool enable{true};
        std::optional<TerminateHook> userHook{std::nullopt};
    };
    struct SignalSettings {
        bool enable{true};
        bool raiseDefaultAfterwards{true};
    };
    struct PanicSettings {
        bool printMsgToStdErr{true};
        bool showPopUp{true};
        bool writeReport{true};
    };
    std::string_view appName;
    std::string_view buildID;
    std::string_view crashDir;
    std::string_view reportFileName{"crash_report.log"};
    bool prefixDateOnFilename{true};
    std::string_view baseErrorMsg{kDefaultErrorMessage};
    bool showPopUp{true};
    bool printMsgToStdErr{true};
    bool useUnsafeStacktraceOnSignalFallback{false};
    bool resolveNonSignalTrace{false};
    SignalSettings signal{};
    TerminateSettings terminate{};
    PanicSettings panic{};
};

struct InitResult {
    bool success{true};
    ConfigWarning warnings{ConfigWarning::kNone};

    explicit operator bool() const {
        return success;
    }
};

// Initializes Fault library. Call this to setup signal handlers, exception handlers, and setup
// additional general parameters. Also recommended to call before using any assertion or panic
// utilities.
// Returns initialization status, along with warning flags. Initialization may only fail if
// messages/paths arguments exceed buffer sizes, or if the report location path is invalid.
FAULT_EXPORT InitResult init(const Config& config = {}) noexcept;

// Stores shutdown request, returning wether this is the first request made.
// @Note Thread-safe
FAULT_EXPORT bool setShutdownRequest() noexcept;

// Returns wether any shutdown request has been made.
[[nodiscard]] FAULT_EXPORT bool hasShutdownRequest() noexcept;

// Returns wether a signal safe object trace can be collected. If false and option to collect
// regular trace is not selected, then no trace will be attempted on signal handlers or Windows
// exception handlers
[[nodiscard]] FAULT_EXPORT bool canSafeTraceBeCollected() noexcept;

// Use this to immediately shutdown the application and perform similar actions as the fault
// handlers, such as error message to stderr, fatal popup and write report.
[[noreturn]] FAULT_EXPORT void panic(
    std::string_view message, const std::optional<ObjectTrace>& exceptionTrace = std::nullopt);

// Assertion Handler. Similar to panic, but using general configuration parameters, and with
// metadata information
[[noreturn]] FAULT_EXPORT void assertionFailure(std::string_view expr, std::string_view file,
                                                std::uint32_t line, std::string_view func,
                                                std::string_view userMsg = {});

[[noreturn]] FAULT_EXPORT void assertionFailure(std::string_view expr, std::source_location loc,
                                                std::string_view userMsg = {});

// NOLINTBEGIN
#define FAULT_ASSERT(condition, ...)                                                          \
    do {                                                                                      \
        if (!(condition)) [[unlikely]] {                                                      \
            fault::assertionFailure(#condition, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
        }                                                                                     \
    } while (0)

#define FAULT_ASSERT2(condition, ...)                                                            \
    do {                                                                                         \
        if (!(condition)) [[unlikely]] {                                                         \
            fault::assertionFailure(#condition, std::source_location::current(), ##__VA_ARGS__); \
        }                                                                                        \
    } while (0)

#ifdef NDEBUG
#define DFAULT_ASSERT(cond, ...) ((void)0)
#else
#define DFAULT_ASSERT(cond, ...) FAULT_ASSERT(cond, ##__VA_ARGS__)
#endif

// NOLINTEND

}  // namespace fault

#endif  // FAULT_HPP