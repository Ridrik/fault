cmake_minimum_required(VERSION 4.1.1)

set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

project(faultproject VERSION 0.1.0 LANGUAGES C CXX)

option(FAULT_BUILD_SHARED "Build fault as a shared library" ON)
if(FAULT_BUILD_SHARED)
    message(STATUS "Building fault as shared library")
    add_library(fault SHARED
        src/fault.cpp
    )
else()
    message(STATUS "Building fault as static library")
    add_library(fault STATIC
        src/fault.cpp
    )
endif()

add_library(fault::fault ALIAS fault)

add_subdirectory(extern) # cpptrace

target_include_directories(fault PUBLIC 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_compile_features(fault PUBLIC cxx_std_23)

set_target_properties(fault PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    GENERATE_EXPORT_HEADER ON
)

if(WIN32)
    target_link_libraries(fault PRIVATE
        ws2_32 mswsock Shcore Psapi
        shell32 ole32 # To get AppData location
    )
endif()

target_link_libraries(fault PRIVATE cpptrace::cpptrace)

if(UNIX)
    set_target_properties(fault PROPERTIES 
        INSTALL_RPATH "$ORIGIN"
    )
endif()

include(GenerateExportHeader)
generate_export_header(fault BASE_NAME FAULT EXPORT_FILE_NAME include/fault/fault_export.h)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS fault
    EXPORT fault-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/include/fault/fault_export.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/fault"
)
install(EXPORT fault-targets
    FILE faultTargets.cmake
    NAMESPACE fault::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/fault
)

configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/faultConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/faultConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/fault
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/faultConfig.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/fault
)