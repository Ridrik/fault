/*
 * fault - A C++ and C fault handling library for Linux and Windows, containing signal and
 * exception handlers, as well as user assertions and panic options, generating reports with
 * metadata, raw or resolved traces, and more
 * https://github.com/Ridrik/fault
 *
 * Licensed under the MIT License.
 */

/**
   @brief Linux Signal Handling:
    Searches for `zenity` and `kdialog` on `$PATH`, recording their locations, if any.
    sets signal handlers for: SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT. Each handler
    does the following if triggered: 1. Generate and write object trace to crash report
    directory, 2. prints summary error message on stderr, 3. Displays user popup if available
    (trying zenity, then kdialog). 4. If set, reraises default signal, else exits with no further
    cleanup.

   @brief Windows Exception Handling:
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

   @brief Both platforms Signal / Exception handling
    @Note Thread-safe
    @Note Signal safety is prioritized, noting that safe trace generation is only available on
    certain configurations. User may choose to set a config flag to collect a regular(signal unsafe)
    trace as fallback, to which the report will become a best - effort attempt.This library attempts
    to mitigate this action with deadlock expiration safeguards, so that the expected termination
    behaviour is seen nonetheless.

   @brief Terminate Handling Sets std::terminate handler. Performs the following, depending on init
    config flags: Creates object trace and message with unhandled exception; runs user hook; writes
    the crash report, prints summary message to stderr, and displays user popup, followed by
    raising default abort() if on linux, or terminating process on Windows. On windows, it also
    writes a minidump to a corresponding .dmp file of same name and path as the report.

    @Note On Linux,
    popup is dependent on either zenity or kdialog being found on `$PATH`

 */

#ifndef FAULT_HPP
#define FAULT_HPP

#include "fault/config.h"

#undef FAULT_EXPECT_AT_IMPL
#undef FAULT_EXPECT_IMPL

#define FAULT_EXPECT_AT_IMPL(cond, ...) \
    ::fault::panic_at(#cond, std::source_location::current(), ##__VA_ARGS__)

#if FAULT_USE_LOCATIONS
#define FAULT_EXPECT_IMPL(cond, ...) FAULT_EXPECT_AT_IMPL(cond, ##__VA_ARGS__)
#else
#define FAULT_EXPECT_IMPL(cond, ...) ::fault::verify(false, ##__VA_ARGS__)
#endif

#include <cstdint>
#include <optional>
#include <source_location>
#include <string>
#include <string_view>
#include <vector>

#include <fault/attributes.h>
#include <fault/fault.h>
#include <fault/fault_export.h>

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
    kInvalidPath = 1 << 2,
    kReportPathTooLong = 1 << 3,
    kReportPathWriteTestFailed = 1 << 4,
    kInternalError = 1 << 5
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
        bool raiseDefaultAfterwards{
            true};  // Raises default signal after handling it. Only relevant on linux. For non
                    // posix signals (terminate handler, panic and assert failures), SIGABRT is
                    // raised instead.
        bool storeShutdownRequests{true};  // Registers SIGINT & SIGTERM to store shutdown request
                                           // (no action is actually taken)
    };
    struct PanicSettings {
        bool printMsgToStdErr{true};
        bool showPopUp{true};
        bool writeReport{true};
    };
    std::string_view appName;
    std::string_view buildID;
    std::string_view crashDir;
    std::string_view reportBaseFileName{"crash_report"};
    bool prefixDateOnFilename{true};
    std::string_view baseErrorMsg{kDefaultErrorMessage};
    bool showPopUp{true};
    bool printMsgToStdErr{true};
    bool useUnsafeStacktraceOnSignalFallback{false};
    bool resolveNonSignalTrace{false};
    bool generateMiniDumpWindows{true};
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

/**
 * @brief Initializes Fault library. Call this to setup signal handlers, exception handlers, and
 * setup additional general parameters. Also recommended to call before using any assertion or
 * panic utilities.
 *
 * @param config configuration options
 * @return initialization status, along with warning flags. Initialization may only fail if
 * messages/paths arguments exceed buffer sizes, or if the report location path is invalid.
 */
FAULT_EXPORT InitResult init(const Config& config = {}) noexcept;

/**
 * @brief Stores shutdown request
 *
 * @return returning wether this is the first request made.
 */
FAULT_EXPORT bool set_shutdown_request() noexcept;

/**
 * @brief Returns wether any shutdown request has been made.
 *
 */
FAULT_NODISCARD FAULT_EXPORT bool has_shutdown_request() noexcept;

/**
 * @brief Returns wether a signal safe object trace can be collected. If false and option to
 * collect regular trace is not selected, then no trace will be attempted on signal handlers or
 * Windows exception handlers
 *
 */
FAULT_NODISCARD FAULT_EXPORT bool can_collect_safe_trace() noexcept;

/**
 * @brief Use this to immediately shutdown the application and perform similar actions as the
 * fault handlers, such as printing error message to stderr, displaying a fatal popup and write
 * report with metadata and object trace. On Linux, default abort is raised afterwards, whereas on
 * Windows, if set, a minidump is generated before terminating the process.
 *
 * @param message message to be displayed on report, stderr and popup
 * @param exceptionTrace optional trace. If set, the report will use it instead of a default
 * generated one. Example: provide a trace after handling an exception using
 * cpptrace::raw_trace_from_current_exception().resolve_object_trace() (converting to ObjectTrace)
 *
 */
[[noreturn]] FAULT_EXPORT void panic(
    std::string_view message, const std::optional<ObjectTrace>& exceptionTrace = std::nullopt);

/**
 * @brief Panic version using metadata information, for assertion failures
 *
 * @param expr expression string
 * @param loc source location (file, line, function name)
 * @param userMsg user provided message
 */
[[noreturn]] FAULT_EXPORT void panic_at(std::string_view expr,
                                        std::source_location loc = std::source_location::current(),
                                        std::string_view userMsg = {});

/**
 * @brief Verify invariant. In case of failure, performs panic shutdown, writing object traced
 * report, visual popup and terminal summary, depending on panic settings. Available on all build
 * modes.
 *
 * @param cond condition to verify
 * @param userMsg user message to be displayed & logged
 */
inline void verify(bool cond, std::string_view userMsg = {}) {
    if (!cond) [[unlikely]] {
        panic(userMsg);
        FAULT_UNREACHABLE();
    }
}

/**
 * @brief Similar to verify(), but with location metadata
 *
 * @param cond condition to verify
 * @param userMsg user message to be displayed & logged
 * @param loc location metadata to be displayed & logged
 */
inline void expect_at(bool cond, std::string_view userMsg = {},
                      std::source_location loc = std::source_location::current()) {
    if (!cond) [[unlikely]] {
        panic_at("", loc, userMsg);
        FAULT_UNREACHABLE();
    }
}

/**
 * @brief Similar to verify(), but with location metadata when FAULT_USE_LOCATIONS is defined
 * (default on debug builds)
 *
 * @param cond condition to verify
 * @param userMsg user message to be displayed & logged
 * @param loc location metadata to be displayed & logged
 */
inline void expect(bool cond, std::string_view userMsg = {}
#if FAULT_USE_LOCATIONS
                   ,
                   std::source_location loc = std::source_location::current()
#endif
) {
    if (!cond) [[unlikely]] {
#if FAULT_USE_LOCATIONS
        expect_at(false, userMsg, loc);
#else
        verify(false, userMsg);
#endif
    }
}

}  // namespace fault

#endif  // FAULT_HPP