#ifndef FAULT_H
#define FAULT_H

// NOLINTBEGIN(modernize-*)

#include <stdint.h>

#include <fault/attributes.h>
#include <fault/config.h>
#include <fault/fault_export.h>
#include <fault/macros.h>

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

typedef struct SignalSettingsV1 {
    bool enable;
    bool raiseDefaultAfterwards;
    bool storeShutdownRequests;
} SignalSettingsV1;

typedef struct PanicSettingsV1 {
    bool printMsgToStdErr;
    bool showPopUp;
    bool writeReport;
} PanicSettingsV1;

typedef struct FaultConfigV1 {
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
    bool enableTerminate;  // In case you're a C++ user below C++20 (defaults to false)
    struct SignalSettingsV1 signal;
    struct PanicSettingsV1 panic;
} FaultConfigV1;

typedef enum FaultConfigWarningV1 {
    kNone = 0,
    kAlreadyInitialized = 1 << 0,
    kBaseErrMsgTruncated = 1 << 1,
    kReportPathTooLong = 1 << 2,
    kReportPathWriteTestFailed = 1 << 3,
    kInternalError = 1 << 4
} FaultConfigWarningV1;

typedef struct FaultInitResultV1 {
    bool success;
    enum FaultConfigWarningV1 warnings;
} FaultInitResultV1;

FAULT_EXPORT FaultConfigV1 fault_get_default_config_v1() FAULT_NOEXCEPT;

FAULT_EXPORT FaultInitResultV1 fault_init_v1(const FaultConfigV1* config) FAULT_NOEXCEPT;

// Stores shutdown request, returning wether the request had already been made before or by another
// thread concurrently.
// @Note Thread-safe
FAULT_EXPORT bool fault_set_shutdown_request() FAULT_NOEXCEPT;

// Returns wether any shutdown request has been made.
FAULT_NODISCARD FAULT_EXPORT bool fault_has_shutdown_request() FAULT_NOEXCEPT;

FAULT_NODISCARD FAULT_EXPORT bool fault_can_collect_safe_trace() FAULT_NOEXCEPT;

FAULT_NORETURN FAULT_EXPORT void fault_panic_v1(const char* message) FAULT_NOEXCEPT;

FAULT_NORETURN FAULT_EXPORT void fault_panic_at_v1(const char* expr, const char* file,
                                                   uint32_t line, const char* func,
                                                   const char* userMsg) FAULT_NOEXCEPT;

typedef const char* (*fault_msg_callback_t)(void* user_data);

FAULT_NORETURN static inline void fault_panic_at_c_v1(const char* expr, const char* file,
                                                      uint32_t line, const char* func,
                                                      fault_msg_callback_t callback,
                                                      void* user_data) FAULT_NOEXCEPT {
    fault_panic_at_v1(expr, file, line, func, callback(user_data));
    FAULT_UNREACHABLE();
}

static inline void fault_verify_v1(bool cond, const char* message) FAULT_NOEXCEPT {
    if (FAULT_EXPECT_FALSE(!(cond)))
        FAULT_UNLIKELY {
            fault_panic_v1(message);
            FAULT_UNREACHABLE();
        }
}

static inline void fault_verify_c_v1(bool cond, fault_msg_callback_t callback,
                                     void* user_data) FAULT_NOEXCEPT {
    if (FAULT_EXPECT_FALSE(!(cond)))
        FAULT_UNLIKELY {
            fault_panic_v1(callback(user_data));
            FAULT_UNREACHABLE();
        }
}

typedef struct fault_panic_guard_s_v1* fault_panic_guard_handle_v1;
typedef enum FaultHookScopeV1 { kThreadLocal, kGlobal } FaultHookScopeV1;

typedef void (*fault_panic_callback_t_v1)(char* buffer, size_t buf_size, void* userData);

FAULT_NODISCARD FAULT_EXPORT fault_panic_guard_handle_v1 fault_register_hook_v1(
    fault_panic_callback_t_v1 cb, void* userData, FaultHookScopeV1 scope) FAULT_NOEXCEPT;

FAULT_EXPORT void fault_release_hook_v1(fault_panic_guard_handle_v1* handle) FAULT_NOEXCEPT;

// ====== Default versions ======
typedef SignalSettingsV1 SignalSettings;
typedef PanicSettingsV1 PanicSettings;
typedef FaultConfigV1 FaultConfig;
typedef FaultConfigWarningV1 FaultConfigWarning;
typedef FaultInitResultV1 FaultInitResult;
typedef fault_panic_callback_t_v1 fault_panic_callback_t;
typedef fault_panic_guard_handle_v1 fault_panic_guard_handle;
typedef FaultHookScopeV1 FaultHookScope;

static inline fault_panic_guard_handle fault_register_hook(fault_panic_callback_t cb,
                                                           void* user_data,
                                                           FaultHookScope scope) FAULT_NOEXCEPT {
    return fault_register_hook_v1(cb, user_data, scope);
}

static inline void fault_release_hook(fault_panic_guard_handle* handle) FAULT_NOEXCEPT {
    fault_release_hook_v1(handle);
}

static inline FaultConfig fault_get_default_config() FAULT_NOEXCEPT {
    return fault_get_default_config_v1();
}

static inline FaultInitResult fault_init(const FaultConfig* config) FAULT_NOEXCEPT {
    return fault_init_v1(config);
}

FAULT_NORETURN static inline void fault_panic(const char* message) FAULT_NOEXCEPT {
    fault_panic_v1(message);
}

static inline void fault_verify(bool cond, const char* message) FAULT_NOEXCEPT {
    fault_verify_v1(cond, message);
}

static inline void fault_verify_c(bool cond, fault_msg_callback_t callback,
                                  void* user_data) FAULT_NOEXCEPT {
    fault_verify_c_v1(cond, callback, user_data);
}
// ==============================

// NOLINTBEGIN
#if FAULT_ASSERT_ACTIVE
#define FAULT_DHOOK_ADD_V1(hook, user_data, scope) fault_register_hook_v1(hook, user_data, scope)
#define FAULT_DHOOK_DEL_V1(handle) fault_release_hook_v1(handle)
#else
#define FAULT_DHOOK_ADD_V1(hook, user_data, scope) NULL
#define FAULT_DHOOK_DEL_V1(handle) ((void)(handle))
#endif

#if FAULT_API_VERSION == 1
#define FAULT_DHOOK_ADD FAULT_DHOOK_ADD_V1
#define FAULT_DHOOK_DEL FAULT_DHOOK_DEL_V1
#else
#define FAULT_DHOOK_ADD
#define FAULT_DHOOK_DEL
#endif

#ifndef FAULT_EXPECT_AT_IMPL
#define FAULT_EXPECT_AT_IMPL_V1(cond, ...) \
    fault_panic_at_v1(#cond, __FILE__, __LINE__, __func__ __VA_OPT__(, ) __VA_ARGS__)
#if FAULT_API_VERSION == 1
#define FAULT_EXPECT_AT_IMPL FAULT_EXPECT_AT_IMPL_V1
#else
#define FAULT_EXPECT_AT_IMPL
#endif
#endif

#define FAULT_EXPECT_AT_C_IMPL_V1(cond, ...) \
    fault_panic_at_c_v1(#cond, __FILE__, __LINE__, __func__ __VA_OPT__(, ) __VA_ARGS__)

#if FAULT_API_VERSION == 1
#define FAULT_EXPECT_AT_C_IMPL FAULT_EXPECT_AT_C_IMPL_V1
#else
#define FAULT_EXPECT_AT_C_IMPL
#endif

#ifndef FAULT_VERIFY_IMPL
#define FAULT_VERIFY_IMPL(cond, ...) fault_verify(false __VA_OPT__(, ) __VA_ARGS__)
#endif

#define FAULT_VERIFY_C_IMPL(cond, ...) fault_verify_c(false __VA_OPT__(, ) __VA_ARGS__)

#ifndef FAULT_EXPECT_IMPL
#if FAULT_USE_LOCATIONS
#define FAULT_EXPECT_IMPL_V1(cond, ...) FAULT_EXPECT_AT_IMPL_V1(#cond __VA_OPT__(, ) __VA_ARGS__)
#else
#define FAULT_EXPECT_IMPL_V1(cond, ...) FAULT_VERIFY_IMPL_V1(false __VA_OPT__(, ) __VA_ARGS__)
#endif
#if FAULT_API_VERSION == 1
#define FAULT_EXPECT_IMPL FAULT_EXPECT_IMPL_V1
#else
#define FAULT_EXPECT_IMPL
#endif
#endif

#if FAULT_USE_LOCATIONS
#define FAULT_EXPECT_C_IMPL_V1(cond, ...) \
    FAULT_EXPECT_AT_C_IMPL_V1(#cond __VA_OPT__(, ) __VA_ARGS__)
#else
#define FAULT_EXPECT_C_IMPL_V1(cond, ...) fault_verify_c_v1(false __VA_OPT__(, ) __VA_ARGS__)
#endif
#if FAULT_API_VERSION == 1
#define FAULT_EXPECT_C_IMPL FAULT_EXPECT_C_IMPL_V1
#else
#define FAULT_EXPECT_C_IMPL
#endif

#define FAULT_VERIFY_C(cond, ...)                                     \
    do {                                                              \
        if (FAULT_EXPECT_FALSE(!(cond)))                              \
            FAULT_UNLIKELY {                                          \
                FAULT_VERIFY_C_IMPL(cond __VA_OPT__(, ) __VA_ARGS__); \
                FAULT_UNREACHABLE();                                  \
            }                                                         \
    } while (0)

#define FAULT_EXPECT_AT_C(cond, ...)                                     \
    do {                                                                 \
        if (FAULT_EXPECT_FALSE(!(cond)))                                 \
            FAULT_UNLIKELY {                                             \
                FAULT_EXPECT_AT_C_IMPL(cond __VA_OPT__(, ) __VA_ARGS__); \
                FAULT_UNREACHABLE();                                     \
            }                                                            \
    } while (0)

#define FAULT_EXPECT_C(cond, ...)                                     \
    do {                                                              \
        if (FAULT_EXPECT_FALSE(!(cond)))                              \
            FAULT_UNLIKELY {                                          \
                FAULT_EXPECT_C_IMPL(cond __VA_OPT__(, ) __VA_ARGS__); \
                FAULT_UNREACHABLE();                                  \
            }                                                         \
    } while (0)

#if FAULT_ASSERT_ACTIVE
#define FAULT_ASSERT_C(cond, ...) FAULT_EXPECT_AT_C(cond __VA_OPT__(, ) __VA_ARGS__)
#else
#define FAULT_ASSERT_C(cond, ...) ((void)0)
#endif
// NOLINTEND

#ifdef __cplusplus
}  // extern "C"
#endif

// NOLINTEND(modernize-*)

#endif  // FAULT_H