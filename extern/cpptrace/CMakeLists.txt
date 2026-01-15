include(FetchContent)

if(NOT DEFINED CPPTRACE_UNWIND_WITH_LIBUNWIND)
    set(CPPTRACE_UNWIND_WITH_LIBUNWIND ON CACHE BOOL "Libunwind is recommended for signal-safe trace unwind" FORCE)
endif()
if((NOT DEFINED CPPTRACE_BUILD_SHARED) AND (NOT DEFINED BUILD_SHARED_LIBS))
    set(CPPTRACE_BUILD_SHARED ON CACHE BOOL "Build cpptrace as shared library to bundle it" FORCE)
endif()
set(PREV_SCAN_SETTING ${CMAKE_CXX_SCAN_FOR_MODULES})
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
FetchContent_Declare(
  cpptrace
  GIT_REPOSITORY https://github.com/jeremy-rifkin/cpptrace.git
  GIT_TAG        ${FAULT_CPPTRACE_TAG} 
)
FetchContent_MakeAvailable(cpptrace)
set(CMAKE_CXX_SCAN_FOR_MODULES ${PREV_SCAN_SETTING})