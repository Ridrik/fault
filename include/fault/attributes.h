#ifndef FAULT_ATTRIBUTES_H
#define FAULT_ATTRIBUTES_H

// noreturn
#if defined(__cplusplus)
#if __cplusplus >= 201103L
#define FAULT_NORETURN [[noreturn]]
#elif defined(_MSC_VER)
#define FAULT_NORETURN __declspec(noreturn)
#elif defined(__GNUC__) || defined(__clang__)
#define FAULT_NORETURN __attribute__((noreturn))
#else
#define FAULT_NORETURN
#endif
#else /* C */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
#define FAULT_NORETURN _Noreturn
#elif defined(_MSC_VER)
#define FAULT_NORETURN __declspec(noreturn)
#elif defined(__GNUC__) || defined(__clang__)
#define FAULT_NORETURN __attribute__((noreturn))
#else
#define FAULT_NORETURN
#endif
#endif

// nodiscard
#if defined(__cplusplus)
#if __cplusplus >= 201703L
#define FAULT_NODISCARD [[nodiscard]]
#elif defined(__GNUC__) || defined(__clang__)
#define FAULT_NODISCARD __attribute__((warn_unused_result))
#elif defined(_MSC_VER)
#define FAULT_NODISCARD _Check_return_
#else
#define FAULT_NODISCARD
#endif
#else /* C */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#define FAULT_NODISCARD [[nodiscard]]
#elif defined(__GNUC__) || defined(__clang__)
#define FAULT_NODISCARD __attribute__((warn_unused_result))
#else
#define FAULT_NODISCARD
#endif
#endif

// unlikely
#if defined(__GNUC__) || defined(__clang__)
#define FAULT_UNLIKELY(expr) __builtin_expect(!!(expr), 0)
#else
#define FAULT_UNLIKELY(expr) (expr)
#endif

// unreachable

#if defined(__cplusplus)

#if __cplusplus >= 202302L
#include <utility>
#define FAULT_UNREACHABLE() std::unreachable()
#elif defined(__GNUC__) || defined(__clang__)
#define FAULT_UNREACHABLE() __builtin_unreachable()
#elif defined(_MSC_VER)
#define FAULT_UNREACHABLE() __assume(false)
#else
#include <cstdlib>
#define FAULT_UNREACHABLE() std::abort()
#endif

#else /* C */

#if defined(__GNUC__) || defined(__clang__)
#define FAULT_UNREACHABLE() __builtin_unreachable()
#elif defined(_MSC_VER)
#define FAULT_UNREACHABLE() __assume(0)
#else
#include <stdlib.h>
#define FAULT_UNREACHABLE() abort()
#endif

#endif

#endif  // FAULT_ATTRIBUTES_H