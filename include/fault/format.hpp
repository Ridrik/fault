#ifndef FAULT_FORMAT_HPP
#define FAULT_FORMAT_HPP

#include <format>

#include <fault/core.hpp>

// NOLINTBEGIN
#define FAULT_EXPECT_AT_FMT(cond, ...)                                              \
    do {                                                                            \
        if (FAULT_EXPECT_FALSE(!(cond)))                                            \
            FAULT_UNLIKELY {                                                        \
                ::fault::expect_at_fmt_impl(#cond, std::source_location::current(), \
                                            ##__VA_ARGS__);                         \
                FAULT_UNREACHABLE();                                                \
            }                                                                       \
    } while (0)

#if FAULT_USE_LOCATIONS
#define FAULT_EXPECT_FMT_IMPL(cond, ...) FAULT_EXPECT_AT_FMT(#cond, ##__VA_ARGS__)
#else
#define FAULT_EXPECT_FMT_IMPL(cond, ...) ::fault::verify(false, ##__VA_ARGS__)
#endif

#define FAULT_EXPECT_FMT(cond, ...)                         \
    do {                                                    \
        if (FAULT_EXPECT_FALSE(!(cond)))                    \
            FAULT_UNLIKELY {                                \
                FAULT_EXPECT_FMT_IMPL(cond, ##__VA_ARGS__); \
                FAULT_UNREACHABLE();                        \
            }                                               \
    } while (0)

// NOLINTEND

namespace fault {

/**
 * @brief panic version with format string
 */
template <typename... Args>
FAULT_NORETURN inline void panic_fmt(std::format_string<Args...> fmt, Args&&... args) {
    panic(std::format(fmt, std::forward<Args>(args)...), std::nullopt);
    FAULT_UNREACHABLE();
}

/**
 * @brief Verify invariant version with format args
 */
template <typename... Args>
inline void verify(bool cond, std::format_string<Args...> fmt, Args&&... args) {
    if (!cond) [[unlikely]] {
        panic(std::format(fmt, std::forward<Args>(args)...));
        FAULT_UNREACHABLE();
    }
}

template <class... Args>
struct PanicFormat {
    template <class T>
    consteval PanicFormat(const T& s,
                          std::source_location loc = std::source_location::current()) noexcept
        : fmt{s}, loc{loc} {}

    std::format_string<Args...> fmt;
    std::source_location loc;
};

/**
 * @brief Implementation version with format string for macros. Users aren't expected to call it
directly. See fault::expect_at overload or FAULT_EXPECT_AT_FMT macro.
 *
 */
template <typename... Args>
inline void expect_at_fmt_impl(std::string_view expr, std::source_location loc,
                               std::format_string<Args...> fmt, Args&&... args) {
    panic_at(expr, loc, std::format(fmt, std::forward<Args>(args)...));
}

/**
 * @brief expect_at overload for format strings
 */
template <class... Args>
void expect_at(bool cond, PanicFormat<std::type_identity_t<Args>...> fmt, Args&&... args) noexcept {
    if (!cond) [[unlikely]] {
        panic_at("", fmt.loc, std::format(fmt.fmt, std::forward<Args>(args)...));
        FAULT_UNREACHABLE();
    }
}

/**
 * @brief expect overload for format strings
 */
template <class... Args>
#if FAULT_USE_LOCATIONS
inline void expect(bool cond, PanicFormat<std::type_identity_t<Args>...> fmt, Args&&... args) {
    if (!cond) [[unlikely]] {
        expect_at(false, fmt, std::forward<Args>(args)...);
        FAULT_UNREACHABLE();
    }
}
#else
inline void expect(bool cond, std::format_string<Args...> fmt, Args&&... args) {
    if (!cond) [[unlikely]] {
        verify(false, fmt, std::forward<Args>(args)...);
        FAULT_UNREACHABLE();
    }
}
#endif

}  // namespace fault

#endif  // FAULT_FORMAT_HPP