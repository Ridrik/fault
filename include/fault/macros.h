#ifndef FAULT_MACROS_H
#define FAULT_MACROS_H

#include "fault/attributes.h"

// NOLINTBEGIN
#define FAULT_VERIFY(cond, ...)                         \
    do {                                                \
        if (FAULT_EXPECT_FALSE(!(cond)))                \
            FAULT_UNLIKELY {                            \
                FAULT_VERIFY_IMPL(cond, ##__VA_ARGS__); \
                FAULT_UNREACHABLE();                    \
            }                                           \
    } while (0)

#define FAULT_EXPECT_AT(cond, ...)                         \
    do {                                                   \
        if (FAULT_EXPECT_FALSE(!(cond)))                   \
            FAULT_UNLIKELY {                               \
                FAULT_EXPECT_AT_IMPL(cond, ##__VA_ARGS__); \
                FAULT_UNREACHABLE();                       \
            }                                              \
    } while (0)

#define FAULT_EXPECT(cond, ...)                         \
    do {                                                \
        if (FAULT_EXPECT_FALSE(!(cond)))                \
            FAULT_UNLIKELY {                            \
                FAULT_EXPECT_IMPL(cond, ##__VA_ARGS__); \
                FAULT_UNREACHABLE();                    \
            }                                           \
    } while (0)

#if FAULT_ASSERT_ACTIVE
#define FAULT_ASSERT(cond, ...) FAULT_EXPECT_AT(cond, ##__VA_ARGS__)
#else
#define FAULT_ASSERT(cond, ...) ((void)0)
#endif
// NOLINTEND

#endif  // FAULT_MACROS_H