cmake_minimum_required(VERSION 3.21...4.1)

set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

project(fault VERSION 0.3.0 LANGUAGES C CXX)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/version.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/fault/version.h"
)

if(UNIX AND NOT APPLE)
    find_program(ZENITY_EXECUTABLE zenity)
    find_program(KDIALOG_EXECUTABLE kdialog)

    if(NOT ZENITY_EXECUTABLE AND NOT KDIALOG_EXECUTABLE)
        message(STATUS "fault: Note: Neither 'zenity' nor 'kdialog' found in PATH. "
                       "Runtime popups will not be displayed unless one is installed at runtime.")
    endif()
endif()

if(MSVC)
    add_compile_options(/Zc:preprocessor) # __VA_OPT__
endif()

set(FAULT_SOURCES
    "src/fault.cpp"
    "include/fault/fault.hpp"
    "include/fault/fault.h"
    "include/fault/core.hpp"
    "include/fault/format.hpp"
    "include/fault/attributes.h"
    "include/fault/config.h"
)
set(FAULT_GENERATED_HEADERS
    "${CMAKE_CURRENT_BINARY_DIR}/generated/fault/version.h"
    "${CMAKE_CURRENT_BINARY_DIR}/include/fault/fault_export.h"
)

if (NOT DEFINED BUILD_SHARED_LIBS)
    set(BUILD_SHARED_LIBS ON) # let fault default to shared library
endif()

option(FAULT_BUILD_SHARED "Build fault as a shared library" ${BUILD_SHARED_LIBS})
if(FAULT_BUILD_SHARED)
    message(STATUS "Building fault as shared library")
    add_library(fault SHARED ${FAULT_SOURCES} ${FAULT_GENERATED_HEADERS})
else()
    message(STATUS "Building fault as static library")
    add_library(fault STATIC ${FAULT_SOURCES} ${FAULT_GENERATED_HEADERS})
endif()

add_library(fault::fault ALIAS fault)

add_subdirectory(extern) # cpptrace

add_library(fault_adapter INTERFACE)
add_library(fault::fault_adapter ALIAS fault_adapter)
target_link_libraries(fault_adapter INTERFACE fault cpptrace::cpptrace)

target_include_directories(fault PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(fault PRIVATE cxx_std_20)

set_target_properties(fault PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    GENERATE_EXPORT_HEADER ON
)

if(WIN32)
    target_link_libraries(fault PRIVATE
        ws2_32 dbghelp ole32
    )
    target_compile_definitions(fault PRIVATE NOMINMAX) # prevent Windows min/max macros
endif()

target_link_libraries(fault PRIVATE cpptrace::cpptrace)

set(FAULT_LOCATIONS "DEFAULT" CACHE STRING "fault source location metadata for fault::expect(): ON, OFF, or DEFAULT(OFF on non-debug/NDEBUG)")

if(FAULT_LOCATIONS STREQUAL "ON")
    target_compile_definitions(fault PUBLIC FAULT_ENABLE_LOCATIONS)
elseif(FAULT_LOCATIONS STREQUAL "OFF")
    target_compile_definitions(fault PUBLIC FAULT_DISABLE_LOCATIONS)
endif()

set(FAULT_ASSERTIONS "DEFAULT" CACHE STRING "fault assertions: ON, OFF, or DEFAULT(OFF on non-debug/NDEBUG)")

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

option(FAULT_INSTALL "Generate install rules for fault" ${PROJECT_IS_TOP_LEVEL})

if(FAULT_INSTALL)
    message(STATUS "fault: Install rules enabled")
    include(cmake/install.cmake)
    include(CTest)
    add_subdirectory(tests)
else()
    message(STATUS "fault: Skipping install rules")
endif()