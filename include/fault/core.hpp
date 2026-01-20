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

#ifndef FAULT_CORE_HPP
#define FAULT_CORE_HPP

#if (defined(_MSVC_LANG) && _MSVC_LANG < 202002L) || (!defined(_MSVC_LANG) && __cplusplus < 202002L)
#error "Fault C++ headers require C++20. Use 'fault.h' for older C++ or C projects."
#endif

#include "fault/config.h"

#undef FAULT_EXPECT_AT_IMPL
#undef FAULT_EXPECT_IMPL
#undef FAULT_VERIFY_IMPL
#undef FAULT_EXPECT_AT_IMPL_V1
#undef FAULT_EXPECT_IMPL_V1
#undef FAULT_VERIFY_IMPL_V1

#define FAULT_EXPECT_AT_IMPL_V1(cond, ...) \
    ::fault::v1::panic_at(#cond, std::source_location::current() __VA_OPT__(, ) __VA_ARGS__)

#define FAULT_VERIFY_IMPL_V1(cond, ...) ::fault::v1::panic(__VA_ARGS__)

#if FAULT_USE_LOCATIONS
#define FAULT_EXPECT_IMPL_V1(cond, ...) FAULT_EXPECT_AT_IMPL_V1(cond __VA_OPT__(, ) __VA_ARGS__)
#else
#define FAULT_EXPECT_IMPL_V1(cond, ...) FAULT_VERIFY_IMPL_V1(false __VA_OPT__(, ) __VA_ARGS__)
#endif

#if FAULT_ASSERT_ACTIVE
#define FAULT_PANIC_GUARD_V1(hook) fault::v1::PanicGuard(hook)
#else
#define FAULT_PANIC_GUARD_V1(hook) ((void)0)
#endif

#if FAULT_API_VERSION == 1
#define FAULT_VERIFY_IMPL FAULT_VERIFY_IMPL_V1
#define FAULT_EXPECT_AT_IMPL FAULT_EXPECT_AT_IMPL_V1
#define FAULT_EXPECT_IMPL FAULT_EXPECT_IMPL_V1
#define FAULT_PANIC_GUARD FAULT_PANIC_GUARD_V1
#else
#define FAULT_VERIFY_IMPL
#define FAULT_EXPECT_AT_IMPL
#define FAULT_EXPECT_IMPL
#define FAULT_PANIC_GUARD
#endif

#include <cstdint>
#include <exception>
#include <functional>
#include <source_location>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <fault/attributes.h>
#include <fault/fault_export.h>
#include <fault/macros.h>

namespace fault {

constexpr std::string_view kDefaultErrorMessage{
    "The application encountered a fatal error and must close. If the problem "
    "persists, please "
    "contact the program maintainer."};

/**
 * @brief Returns wether fault has a saved exception from fault::save_traced_exception.
 *
 */
FAULT_NODISCARD FAULT_EXPORT bool has_saved_traced_exception() noexcept;

#if FAULT_API_VERSION == 1
inline
#endif
    namespace v1 {

struct FAULT_EXPORT Frame {
    std::uintptr_t rawAddress{};
    std::uintptr_t objAddress{};
    std::string objPath;
};

struct FAULT_EXPORT ObjectTrace {
    std::vector<Frame> frames;
};

using TerminateHook = void (*)(std::string_view userMessage, ObjectTrace& objectTrace);

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
        TerminateHook userHook{nullptr};
    };
    struct SignalSettings {
        bool enable{true};
        bool raiseDefaultAfterwards{
            true};  // Raises default signal after handling it. Only relevant on linux. For non
                    // posix signals (terminate handler, panic and assert failures), SIGABRT is
                    // raised instead.
        bool storeShutdownRequests{true};  // Registers SIGINT & SIGTERM to store shutdown
                                           // request (no action is actually taken)
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

using PanicHook = std::function<std::string()>;

enum class HookScope : std::uint8_t { kThreadLocal, kGlobal };

struct FAULT_EXPORT PanicGuard {
   public:
    explicit PanicGuard(PanicHook callback, HookScope scope = HookScope::kThreadLocal);
    ~PanicGuard();
    PanicGuard(const PanicGuard&) = delete;
    PanicGuard& operator=(const PanicGuard&) = delete;
    PanicGuard(PanicGuard&&) = delete;
    PanicGuard& operator=(PanicGuard&&) = delete;

    void release() noexcept;

   private:
    std::size_t idx_{0};
    HookScope scope_;
    bool active_{false};
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
 * @brief Saves a traced exception, which will later automatically be appended on panic or
 * std::terminate handling.
 * Example: Save a traced exception from a thread, signal main thread with shutdown request,
 * main thread does cleanup and panics if exception is saved
 *
 * @note Thread-safe
 * @note Not async-signal-safe (implied)
 */
FAULT_EXPORT void save_traced_exception(std::string_view msg,
                                        const ObjectTrace* customTrace = nullptr) noexcept;

/**
 * @brief panic implementation
 *
 * @param message message to be displayed on report, stderr and popup
 * @param customTrace Optional bject trace to be logged instead of default generated one.
 */
[[noreturn]] FAULT_EXPORT void panic_impl(std::string_view message,
                                          const ObjectTrace* customTrace = nullptr);

/**
 * @brief Use this to immediately shutdown the application and perform similar actions as the
 * fault handlers, such as printing error message to stderr, displaying a fatal popup and write
 * report with metadata and object trace. On Linux, default abort is raised afterwards, whereas
 * on Windows, if set, a minidump is generated before terminating the process.
 *
 * @param message message to be displayed on report, stderr and popup
 *
 */
[[noreturn]] inline void panic(std::string_view message = {}) {
    panic_impl(message, nullptr);
    FAULT_UNREACHABLE();
}

/**
 * @brief panics if any exception was saved via fault::save_traced_exception.
 * @note for higher customization, user may instead check fault::has_saved_traced_exception, and
 * if so explicitly panic with one of its overloads
 *
 */
inline void panic_if_has_saved_exception(std::string_view message = {}) noexcept {
    if (has_saved_traced_exception()) {
        panic(message);
        FAULT_UNREACHABLE();
    }
}

/**
 * @brief panic version with trace override for report.
 *
 * @param trace Object trace to be logged instead of default generated one.
 * @param message message to be displayed on report, stderr and popup
 */
[[noreturn]] inline void panic(const ObjectTrace& trace, std::string_view message = {}) {
    panic_impl(message, &trace);
    FAULT_UNREACHABLE();
}

/**
 * @brief Panic version using metadata information, for invariant failures with source location.
 *
 * @param expr expression string
 * @param loc source location (file, line, function name)
 * @param userMsg user provided message
 */
[[noreturn]] FAULT_EXPORT void panic_at(std::string_view expr,
                                        std::source_location loc = std::source_location::current(),
                                        std::string_view userMsg = {});

/**
 * @brief Panic version using metadata information, for invariant failures with source location.
 * Replaces string_view with a string_view callable, for deferred evaluation.
 *
 * @param expr expression string
 * @param loc source location (file, line, function name)
 * @param msgFn user message to be displayed & logged, as callable
 */
template <typename MsgFn>
    requires std::invocable<MsgFn> &&
             std::convertible_to<std::invoke_result_t<MsgFn>, std::string_view>
[[noreturn]] void panic_at(
    std::string_view expr, std::source_location loc = std::source_location::current(),
    MsgFn&& msgFn = [] { return ""; }) {
    if constexpr (requires { bool(msgFn); }) {
        if (!msgFn) {
            panic_at(expr, loc, "<null message provider>");
            FAULT_UNREACHABLE();
        }
    }
    panic_at(expr, loc, std::invoke(std::forward<MsgFn>(msgFn)));
    FAULT_UNREACHABLE();
}

/**
 * @brief Verify invariant. In case of failure, performs panic shutdown, writing object traced
 * report, visual popup and terminal summary, depending on panic settings. Available on all
 * build modes.
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
 * @brief Verify invariant version with string_view callable, for deferred evaluation.
 *
 * @tparam MsgFn callable
 * @param cond condition to verify
 * @param msgFn user message to be displayed & logged, as callable
 */
template <typename MsgFn>
    requires std::invocable<MsgFn> &&
             std::convertible_to<std::invoke_result_t<MsgFn>, std::string_view>
inline void verify(bool cond, MsgFn&& msgFn) {
    if (!cond) [[unlikely]] {
        if constexpr (requires { bool(msgFn); }) {
            if (!msgFn) {
                panic("<null message provider>");
                FAULT_UNREACHABLE();
            }
        }
        panic(std::invoke(std::forward<MsgFn>(msgFn)));
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
 * @brief expect_at version with string_view callable, for deferred evaluation
 *
 * @tparam MsgFn
 * @param cond condition to verify
 * @param msgFn user message to be displayed & logged, as callable
 * @param loc location metadata to be displayed & logged
 */
template <typename MsgFn>
    requires std::invocable<MsgFn> &&
             std::convertible_to<std::invoke_result_t<MsgFn>, std::string_view>
inline void expect_at(bool cond, MsgFn&& msgFn,
                      std::source_location loc = std::source_location::current()) {
    if (!cond) [[unlikely]] {
        if constexpr (requires { bool(msgFn); }) {
            if (!msgFn) {
                panic_at("", loc, "<null message provider>");
                FAULT_UNREACHABLE();
            }
        }
        panic_at("", loc, std::invoke(std::forward<MsgFn>(msgFn)));
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

/**
 * @brief expect version with string_view callable, for deferred evaluation
 *
 * @param cond condition to verify
 * @param msgFn user message to be displayed & logged, as callable
 * @param loc location metadata to be displayed & logged
 */
template <typename MsgFn>
    requires std::invocable<MsgFn> &&
             std::convertible_to<std::invoke_result_t<MsgFn>, std::string_view>
inline void expect(bool cond, MsgFn&& msgFn
#if FAULT_USE_LOCATIONS
                   ,
                   std::source_location loc = std::source_location::current()
#endif
) {
    if (!cond) [[unlikely]] {
#if FAULT_USE_LOCATIONS
        expect_at(false, std::forward<MsgFn>(msgFn), loc);
#else
        verify(false, std::forward<MsgFn>(msgFn));
#endif
    }
}

enum class CatchPolicy : std::uint8_t { kNothing, kPanic, kSaveExceptionWithShutdownRequest };

/**
 * @brief Wraps and invokes body within a try/catch with default catch blocks: 'const
 * std::exception&' and 'catch all'. If any of these blocks is reached, executes onException, if
 * any, followed by a given policy: panic (@see fault::panic) - in which case it is [[noreturn]]; or
 * saves exception and signals for shutdown (@see fault::has_shutdown_request), returning
 * afterwards; or does nothing and returns.
 *
 * The try/catch block uses cpptrace unwind interceptor, meaning that either policy will
 * automatically contain traces from the current exception (i.e containing the thrown context)
 *
 * @note onException callback contains the exception pointer, which users may use to retrieve
 * suspected exception types, similarly to if they had done the original try/catch themselves. It
 * returns a std::string, which, if non-empty, will be forwarded to fault::panic or to the saved
 * trace message, depending on the policy. If empty, it uses default no-op or std::exception
 * message, whichever block was hit.
 * @note Use this when you want to have traces from exceptions without depending on cpptrace
 * directly.
 *
 * @param body Function to be invocked
 * @param catchPolicy policy to execute on catch event
 * @param onException optional callback to execute on catch event, before the policy is executed. If
 * the return value is non-empty, it is used as panic or saved exception message.
 */
FAULT_EXPORT void try_catch(
    std::function<void()> body, CatchPolicy catchPolicy,
    std::function<std::string(std::exception_ptr ep, const ObjectTrace& trace)> onException =
        nullptr) noexcept;

}  // namespace v1

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

}  // namespace fault

#endif  // FAULT_CORE_HPP