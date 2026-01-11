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
    bool storeShutdownRequests;
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
    const char* reportBaseFileName;
    bool prefixDateOnFilename;
    const char* baseErrorMsg;
    bool showPopUp;
    bool printMsgToStdErr;
    bool useUnsafeStacktraceOnSignalFallback;
    bool resolveNonSignalTrace;
    bool generateMiniDumpWindows;
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

FAULT_NODISCARD FAULT_EXPORT bool fault_can_collect_safe_trace() FAULT_NOEXCEPT;

FAULT_NORETURN FAULT_EXPORT void fault_panic(const char* message);

FAULT_NORETURN FAULT_EXPORT void fault_panic_at(const char* expr, const char* file, uint32_t line,
                                                const char* func, const char* userMsg);

typedef const char* (*fault_msg_callback_t)(void* user_data);

FAULT_NORETURN static inline void fault_panic_at_c(const char* expr, const char* file,
                                                   uint32_t line, const char* func,
                                                   fault_msg_callback_t callback, void* user_data) {
    fault_panic_at(expr, file, line, func, callback(user_data));
    FAULT_UNREACHABLE();
}

static inline void fault_verify(bool cond, const char* message) {
    if (FAULT_EXPECT_FALSE(!(cond)))
        FAULT_UNLIKELY {
            fault_panic(message);
            FAULT_UNREACHABLE();
        }
}

static inline void fault_verify_c(bool cond, fault_msg_callback_t callback, void* user_data) {
    if (FAULT_EXPECT_FALSE(!(cond)))
        FAULT_UNLIKELY {
            fault_panic(callback(user_data));
            FAULT_UNREACHABLE();
        }
}

// NOLINTBEGIN

#ifndef FAULT_EXPECT_AT_IMPL
#define FAULT_EXPECT_AT_IMPL(cond, ...) \
    fault_panic_at(#cond, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#endif

#define FAULT_EXPECT_AT_C_IMPL(cond, ...) \
    fault_panic_at_c(#cond, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

#ifndef FAULT_VERIFY_IMPL
#define FAULT_VERIFY_IMPL(cond, ...) fault_verify(false, ##__VA_ARGS__)
#endif

#define FAULT_VERIFY_C_IMPL(cond, ...) fault_verify_c(false, ##__VA_ARGS__)

#ifndef FAULT_EXPECT_IMPL
#if FAULT_USE_LOCATIONS
#define FAULT_EXPECT_IMPL(cond, ...) FAULT_EXPECT_AT_IMPL(#cond, ##__VA_ARGS__)
#else
#define FAULT_EXPECT_IMPL(cond, ...) FAULT_VERIFY_IMPL(false, ##__VA_ARGS__)
#endif
#endif

#if FAULT_USE_LOCATIONS
#define FAULT_EXPECT_C_IMPL(cond, ...) FAULT_EXPECT_AT_C_IMPL(#cond, ##__VA_ARGS__)
#else
#define FAULT_EXPECT_C_IMPL(cond, ...) FAULT_VERIFY_C_IMPL(false, ##__VA_ARGS__)
#endif

#define FAULT_VERIFY(cond, ...)                         \
    do {                                                \
        if (FAULT_EXPECT_FALSE(!(cond)))                \
            FAULT_UNLIKELY {                            \
                FAULT_VERIFY_IMPL(cond, ##__VA_ARGS__); \
                FAULT_UNREACHABLE();                    \
            }                                           \
    } while (0)

#define FAULT_VERIFY_C(cond, ...)                         \
    do {                                                  \
        if (FAULT_EXPECT_FALSE(!(cond)))                  \
            FAULT_UNLIKELY {                              \
                FAULT_VERIFY_C_IMPL(cond, ##__VA_ARGS__); \
                FAULT_UNREACHABLE();                      \
            }                                             \
    } while (0)

#define FAULT_EXPECT_AT(cond, ...)                         \
    do {                                                   \
        if (FAULT_EXPECT_FALSE(!(cond)))                   \
            FAULT_UNLIKELY {                               \
                FAULT_EXPECT_AT_IMPL(cond, ##__VA_ARGS__); \
                FAULT_UNREACHABLE();                       \
            }                                              \
    } while (0)

#define FAULT_EXPECT_AT_C(cond, ...)                         \
    do {                                                     \
        if (FAULT_EXPECT_FALSE(!(cond)))                     \
            FAULT_UNLIKELY {                                 \
                FAULT_EXPECT_AT_C_IMPL(cond, ##__VA_ARGS__); \
                FAULT_UNREACHABLE();                         \
            }                                                \
    } while (0)

#define FAULT_EXPECT(cond, ...)                         \
    do {                                                \
        if (FAULT_EXPECT_FALSE(!(cond)))                \
            FAULT_UNLIKELY {                            \
                FAULT_EXPECT_IMPL(cond, ##__VA_ARGS__); \
                FAULT_UNREACHABLE();                    \
            }                                           \
    } while (0)

#define FAULT_EXPECT_C(cond, ...)                         \
    do {                                                  \
        if (FAULT_EXPECT_FALSE(!(cond)))                  \
            FAULT_UNLIKELY {                              \
                FAULT_EXPECT_C_IMPL(cond, ##__VA_ARGS__); \
                FAULT_UNREACHABLE();                      \
            }                                             \
    } while (0)

#if FAULT_ASSERT_ACTIVE
#define FAULT_ASSERT(cond, ...) FAULT_EXPECT_AT(cond, ##__VA_ARGS__)
#define FAULT_ASSERT_C(cond, ...) FAULT_EXPECT_AT_C(cond, ##__VA_ARGS__)
#else
#define FAULT_ASSERT(cond, ...) ((void)0)
#define FAULT_ASSERT_C(cond, ...) ((void)0)
#endif
// NOLINTEND
#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // FAULT_H