#ifndef FAULT_FORMAT_HPP
#define FAULT_FORMAT_HPP

#include <format>

#include "fault/core.hpp"

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
 * @brief Verify invariant version with format args
 *
 * @tparam Args
 * @param cond
 * @param fmt
 * @param args
 */
template <typename... Args>
inline void verify(bool cond, std::format_string<Args...> fmt, Args&&... args) {
    if (!cond) [[unlikely]] {
        panic(std::format(fmt, std::forward<Args>(args)...));
        FAULT_UNREACHABLE();
    }
}

template <typename... Args>
inline void expect_at_fmt_impl(std::string_view expr, std::source_location loc,
                               std::format_string<Args...> fmt, Args&&... args) {
    panic_at(expr, loc, std::format(fmt, std::forward<Args>(args)...));
}

}  // namespace fault

#endif  // FAULT_FORMAT_HPP