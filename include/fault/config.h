#ifndef FAULT_CONFIG_H
#define FAULT_CONFIG_H

// --- Location Metadata Configuration ---
#if defined(FAULT_ENABLE_LOCATIONS)
#define FAULT_USE_LOCATIONS 1
#elif defined(FAULT_DISABLE_LOCATIONS) || defined(NDEBUG)
#define FAULT_USE_LOCATIONS 0
#else
#define FAULT_USE_LOCATIONS 1
#endif

// --- Assertion Configuration ---
#if defined(FAULT_FORCE_ASSERTIONS_ON)
#define FAULT_ASSERT_ACTIVE 1
#elif defined(FAULT_FORCE_ASSERTIONS_OFF) || defined(NDEBUG)
#define FAULT_ASSERT_ACTIVE 0
#else
#define FAULT_ASSERT_ACTIVE 1
#endif

#endif  // FAULT_CONFIG_H