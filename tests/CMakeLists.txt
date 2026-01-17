function(add_test_executable name source_file)
    add_executable(${name} ${source_file})

    get_filename_component(ext ${source_file} EXT)
    if(ext STREQUAL ".cpp" OR ext STREQUAL ".cxx" OR ext STREQUAL ".cc")
        # C++ settings
        target_compile_features(${name} PRIVATE cxx_std_20)
        target_link_libraries(${name} PRIVATE fault::fault_adapter)
    elseif(ext STREQUAL ".c")
        # C settings
        set_target_properties(${name} PROPERTIES LINKER_LANGUAGE C)
        target_link_libraries(${name} PRIVATE fault::fault)
    endif()

    target_compile_options(${name} PRIVATE
        $<$<CXX_COMPILER_ID:GNU>:-w>
        $<$<CXX_COMPILER_ID:Clang>:-w>
        $<$<CXX_COMPILER_ID:MSVC>:/w>
    )
    set_target_properties(${name} PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
    if(WIN32)
        add_custom_command(TARGET ${name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:fault::fault>
            $<TARGET_FILE_DIR:${name}>
        )
        add_custom_command(TARGET ${name} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:cpptrace::cpptrace>
            $<TARGET_FILE_DIR:${name}>
        )
    endif()
endfunction()

# ====== Dummy tests (practice area) =======
add_test_executable(test_cpp_api test_cpp_api.cpp)
add_test_executable(test_cpp_api_2 test_cpp_api_2.cpp)
add_test_executable(test_c_api test_c_api.c)


# ====== Crash Target ======
find_package(Boost 1.88 REQUIRED COMPONENTS asio system filesystem process program_options unit_test_framework)
add_test_executable(crash_target crash_target.cpp)
target_link_libraries(crash_target PRIVATE Boost::program_options)
target_compile_definitions(crash_target PRIVATE 
    CRASH_REPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/crash"
)

# ====== Master ======
add_executable(crash_master crash_master.cpp)
target_compile_features(crash_master PRIVATE cxx_std_20)
if(WIN32)
    target_link_libraries(crash_master PRIVATE mswsock)
endif()
target_link_libraries(crash_master PRIVATE fault::fault Boost::unit_test_framework Boost::system Boost::filesystem Boost::process)
target_compile_features(crash_master PRIVATE cxx_std_20)
target_compile_options(crash_master PRIVATE
    $<$<CXX_COMPILER_ID:GNU>:-w>
    $<$<CXX_COMPILER_ID:Clang>:-w>
    $<$<CXX_COMPILER_ID:MSVC>:/w>
)
target_compile_definitions(crash_master PRIVATE 
    CRASH_TARGET_PATH="$<TARGET_FILE:crash_target>"
    CRASH_REPORT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/crash"
)
add_test(NAME test_crash_master COMMAND crash_master WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

# ====== Custom Fault test run ======
add_custom_target(fault_run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)