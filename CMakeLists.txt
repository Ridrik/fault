cmake_minimum_required(VERSION 3.21...4.1)

set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

project(libfault VERSION 0.1.0 LANGUAGES C CXX)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/fault/version.h"
)

set(FAULT_SOURCES
    src/fault.cpp
    include/fault/fault.hpp
    include/fault/fault.h
    include/fault/attributes.h
    include/fault/config.h
)
option(FAULT_BUILD_SHARED "Build libfault as a shared library" ${BUILD_SHARED_LIBS})
if(FAULT_BUILD_SHARED)
    message(STATUS "Building libfault as shared library")
    add_library(fault SHARED ${FAULT_SOURCES})
else()
    message(STATUS "Building libfault as static library")
    add_library(fault STATIC ${FAULT_SOURCES})
endif()

add_library(fault::fault ALIAS fault)

add_library(fault_adapter INTERFACE)
add_library(fault::fault_adapter ALIAS fault_adapter)
target_link_libraries(fault_adapter INTERFACE fault cpptrace::cpptrace)

add_subdirectory(extern) # cpptrace

target_include_directories(fault PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(fault PUBLIC cxx_std_20)

set_target_properties(fault PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    GENERATE_EXPORT_HEADER ON
)

if(WIN32)
    target_link_libraries(fault PRIVATE
        ws2_32 dbghelp ole32
    )
endif()

target_link_libraries(fault PRIVATE cpptrace::cpptrace)

set(FAULT_LOCATIONS "DEFAULT" CACHE STRING "libfault source location metadata for fault::expect(): ON, OFF, or DEFAULT(OFF on non-debug/NDEBUG)")

if(FAULT_LOCATIONS STREQUAL "ON")
    target_compile_definitions(fault PUBLIC FAULT_ENABLE_LOCATIONS)
elseif(FAULT_LOCATIONS STREQUAL "OFF")
    target_compile_definitions(fault PUBLIC FAULT_DISABLE_LOCATIONS)
endif()

set(FAULT_ASSERTIONS "DEFAULT" CACHE STRING "libfault assertions: ON, OFF, or DEFAULT(OFF on non-debug/NDEBUG)")

if(FAULT_ASSERTIONS STREQUAL "ON")
    target_compile_definitions(fault PUBLIC FAULT_FORCE_ASSERTIONS_ON)
elseif(FAULT_ASSERTIONS STREQUAL "OFF")
    target_compile_definitions(fault PUBLIC FAULT_FORCE_ASSERTIONS_OFF)
endif()

if(UNIX)
    set_target_properties(fault PROPERTIES 
        INSTALL_RPATH "$ORIGIN"
    )
endif()

include(GenerateExportHeader)
generate_export_header(fault BASE_NAME FAULT EXPORT_FILE_NAME include/fault/fault_export.h)

option(FAULT_INSTALL "Generate install rules for libfault" ${PROJECT_IS_TOP_LEVEL})

if(FAULT_INSTALL)
    message(STATUS "libfault: Install rules enabled")
    include(cmake/install.cmake)
    add_subdirectory(tests)
else()
    message(STATUS "libfault: Skipping install rules")
endif()