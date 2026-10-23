#ifndef FAULT_FORMAT_HPP
#define FAULT_FORMAT_HPP

#include <format>
#include <optional>
#include <source_location>
#include <string_view>
#include <type_traits>

#include "fault/attributes.h"
#include "fault/config.h"
#include "fault/core.hpp"
#include "fault/macros.h"

namespace fault {  // NOLINT(modernize-concat-nested-namespaces)

MAYBE_INLINED_NAMESPACE_V1 {
    template <typename... Args>
    FAULT_NORETURN inline void panic(std::format_string<Args...> fmt, Args && ... args) noexcept {
        panic_impl(std::format(fmt, std::forward<Args>(args)...), std::nullopt);
        FAULT_UNREACHABLE();
    }

    template <typename... Args>
    FAULT_NORETURN inline void panic(const ObjectTrace& trace, std::format_string<Args...> fmt,
                                     Args&&... args) noexcept {
        panic_impl(std::format(fmt, std::forward<Args>(args)...), &trace);
        FAULT_UNREACHABLE();
    }

    /**
     * @brief Verify invariant version with format args
     */
    template <typename... Args>
    inline void verify(bool cond, std::format_string<Args...> fmt, Args&&... args) noexcept {
        if (!cond) [[unlikely]] {
            panic_impl(std::format(fmt, std::forward<Args>(args)...));
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
    directly. See FAULT_ASSERT, FAULT_EXPECT_AT & fault::expect_at overload or FAULT_EXPECT_AT_FMT
    macro.
     *
     */
    template <typename... Args>
    inline void panic_at(std::string_view expr, std::source_location loc,
                         std::format_string<Args...> fmt, Args && ... args) noexcept {
        panic_at(expr, loc, std::format(fmt, std::forward<Args>(args)...));
    }

    /**
     * @brief expect_at overload for format strings
     */
    template <class... Args>
    void expect_at(bool cond, PanicFormat<std::type_identity_t<Args>...> fmt,
                   Args&&... args) noexcept {
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
    inline void expect(bool cond, PanicFormat<std::type_identity_t<Args>...> fmt,
                       Args&&... args) noexcept {
        if (!cond) [[unlikely]] {
            expect_at(false, fmt, std::forward<Args>(args)...);
            FAULT_UNREACHABLE();
        }
    }
#else
    inline void expect(bool cond, std::format_string<Args...> fmt, Args&&... args) noexcept {
        if (!cond) [[unlikely]] {
            verify(false, fmt, std::forward<Args>(args)...);
            FAULT_UNREACHABLE();
        }
    }
#endif

}  // namespace v1

}  // namespace fault

#endif  // FAULT_FORMAT_HPP