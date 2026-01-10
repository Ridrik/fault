include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS fault fault_adapter
    EXPORT fault-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp"
)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/include/fault/fault_export.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/fault"
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/faultConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
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