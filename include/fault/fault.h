#ifndef FAULT_H
#define FAULT_H

#include "fault/attributes.h"
#include "fault/fault_export.h"

#include <stdint.h>

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

FAULT_EXPORT FaultConfig faultGetDefaultConfig() FAULT_NOEXCEPT;

FAULT_EXPORT FaultInitResult faultInit(const FaultConfig* config) FAULT_NOEXCEPT;

// Stores shutdown request, returning wether the request had already been made before or by another
// thread concurrently.
// @Note Thread-safe
FAULT_EXPORT bool faultSetShutdownRequest() FAULT_NOEXCEPT;

// Returns wether any shutdown request has been made.
FAULT_NODISCARD FAULT_EXPORT bool faultHasShutdownRequest() FAULT_NOEXCEPT;

FAULT_NODISCARD FAULT_EXPORT bool faultCanSafeTraceBeCollected() FAULT_NOEXCEPT;

FAULT_NORETURN FAULT_EXPORT void faultPanic(const char* message);

FAULT_NORETURN FAULT_EXPORT void faultAssertionFailure(const char* expr, const char* file,
                                                       uint32_t line, const char* func,
                                                       const char* userMsg);

static inline void faultVerify(bool cond, const char* message) {
    if (FAULT_UNLIKELY(!(cond))) {
        faultPanic(message);
        FAULT_UNREACHABLE();
    }
}

#ifndef __cplusplus
#ifndef NDEBUG
#define FAULT_EXPECT_IMPL(cond, ...) \
    faultAssertionFailure(#cond, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#else
#define FAULT_EXPECT_IMPL(cond, ...) faultVerify(false, ##__VA_ARGS__)
#endif
#endif

// NOLINTBEGIN
#define FAULT_EXPECT(cond, ...)                     \
    do {                                            \
        if (FAULT_UNLIKELY(!(cond))) {              \
            FAULT_EXPECT_IMPL(cond, ##__VA_ARGS__); \
            FAULT_UNREACHABLE();                    \
        }                                           \
    } while (0)

#ifdef NDEBUG
#define FAULT_ASSERT(cond, ...) ((void)0)
#else
#define FAULT_ASSERT(cond, ...) FAULT_EXPECT(cond, ##__VA_ARGS__)
#endif
// NOLINTEND
#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // FAULT_H