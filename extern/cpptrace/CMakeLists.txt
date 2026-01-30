include(FetchContent)

if((NOT DEFINED CPPTRACE_UNWIND_WITH_LIBUNWIND) AND (NOT MSVC))
    set(CPPTRACE_UNWIND_WITH_LIBUNWIND ON CACHE BOOL "Libunwind is recommended for signal-safe trace unwind" FORCE)
endif()
if((NOT DEFINED CPPTRACE_BUILD_SHARED) AND (NOT DEFINED BUILD_SHARED_LIBS))
    set(CPPTRACE_BUILD_SHARED ON CACHE BOOL "Build cpptrace as shared library to bundle it" FORCE)
endif()
set(PREV_SCAN_SETTING ${CMAKE_CXX_SCAN_FOR_MODULES})
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
FetchContent_Declare(
  cpptrace SYSTEM
  GIT_REPOSITORY https://github.com/jeremy-rifkin/cpptrace.git
  GIT_TAG        ${FAULT_CPPTRACE_TAG} 
)
FetchContent_MakeAvailable(cpptrace)

get_target_property(real_cpptrace cpptrace::cpptrace ALIASED_TARGET)

# cpptrace does not support -fno-exceptions
target_compile_options(${real_cpptrace} PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-fexceptions>
    $<$<CXX_COMPILER_ID:MSVC>:/EHsc>
)

set(CMAKE_CXX_SCAN_FOR_MODULES ${PREV_SCAN_SETTING})