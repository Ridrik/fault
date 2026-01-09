#ifndef FAULT_H
#define FAULT_H

#include <stdint.h>

#include <fault/attributes.h>
#include <fault/config.h>
#include <fault/fault_export.h>

#ifdef __cplusplus
#define FAULT_NOEXCEPT noexcept
extern "C" {
#else
#define FAULT_NOEXCEPT
#include <stdbool.h>
#endif

const char* const kDefaultErrorMessage =
    "The application encountered a fatal error and must close. If the problem "
    "persists, please "
    "contact the program maintainer.";

typedef struct SignalSettings {
    bool enable;
    bool raiseDefaultAfterwards;
} SignalSettings;

typedef struct PanicSettings {
    bool printMsgToStdErr;
    bool showPopUp;
    bool writeReport;
} PanicSettings;

typedef struct FaultConfig {
    const char* appName;
    const char* buildID;
    const char* crashDir;
    const char* reportFileName;
    bool prefixDateOnFilename;
    const char* baseErrorMsg;
    bool showPopUp;
    bool printMsgToStdErr;
    bool useUnsafeStacktraceOnSignalFallback;
    bool resolveNonSignalTrace;
    struct SignalSettings signal;
    struct PanicSettings panic;
} FaultConfig;

enum FaultConfigWarning : uint8_t {
    kNone = 0,
    kAlreadyInitialized = 1 << 0,
    kBaseErrMsgTruncated = 1 << 1,
    kReportPathTooLong = 1 << 2,
    kReportPathWriteTestFailed = 1 << 3,
    kInternalError = 1 << 4
};

typedef struct FaultInitResult {
    bool success;
    enum FaultConfigWarning warnings;
} FaultInitResult;

FAULT_EXPORT FaultConfig fault_get_default_config() FAULT_NOEXCEPT;

FAULT_EXPORT FaultInitResult fault_init(const FaultConfig* config) FAULT_NOEXCEPT;

// Stores shutdown request, returning wether the request had already been made before or by another
// thread concurrently.
// @Note Thread-safe
FAULT_EXPORT bool fault_set_shutdown_request() FAULT_NOEXCEPT;

// Returns wether any shutdown request has been made.
FAULT_NODISCARD FAULT_EXPORT bool fault_has_shutdown_request() FAULT_NOEXCEPT;

FAULT_NODISCARD FAULT_EXPORT bool fault_can_safetrace_becollected() FAULT_NOEXCEPT;

FAULT_NORETURN FAULT_EXPORT void fault_panic(const char* message);

FAULT_NORETURN FAULT_EXPORT void fault_assertion_failure(const char* expr, const char* file,
                                                         uint32_t line, const char* func,
                                                         const char* userMsg);

static inline void fault_verify(bool cond, const char* message) {
    if (FAULT_UNLIKELY(!(cond))) {
        fault_panic(message);
        FAULT_UNREACHABLE();
    }
}

// NOLINTBEGIN

#ifndef __cplusplus

#define FAULT_EXPECT_AT_IMPL(cond, ...) \
    fault_assertion_failure(#cond, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#if FAULT_USE_LOCATIONS
#define FAULT_EXPECT_IMPL(cond, ...) FAULT_EXPECT_AT_IMPL(#cond, ##__VA_ARGS__)
#else
#define FAULT_EXPECT_IMPL(cond, ...) fault_verify(false, ##__VA_ARGS__)
#endif
#endif

#define FAULT_EXPECT_AT(cond, ...)                  \
    do {                                            \
        if (FAULT_UNLIKELY(!(cond))) {              \
            FAULT_EXPECT_IMPL(cond, ##__VA_ARGS__); \
            FAULT_UNREACHABLE();                    \
        }                                           \
    } while (0)

#define FAULT_EXPECT(cond, ...)                     \
    do {                                            \
        if (FAULT_UNLIKELY(!(cond))) {              \
            FAULT_EXPECT_IMPL(cond, ##__VA_ARGS__); \
            FAULT_UNREACHABLE();                    \
        }                                           \
    } while (0)

#if FAULT_ASSERT_ACTIVE
#define FAULT_ASSERT(cond, ...) FAULT_EXPECT(cond, ##__VA_ARGS__)
#else
#define FAULT_ASSERT(cond, ...) ((void)0)
#endif
// NOLINTEND
#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // FAULT_H