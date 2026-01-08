
add_executable(test_cpp_api test_cpp_api.cpp)
target_link_libraries(test_cpp_api PRIVATE fault::fault)
target_compile_features(test_cpp_api PRIVATE cxx_std_20)
set_target_properties(test_cpp_api PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(test_c_api test_c_api.c)
target_link_libraries(test_c_api PRIVATE fault::fault)
set_target_properties(test_c_api PROPERTIES LINKER_LANGUAGE C WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

enable_testing()
add_test(NAME cpp_api_test COMMAND test_cpp_api)
add_test(NAME c_api_test COMMAND test_c_api)

if(WIN32)
    add_custom_command(TARGET test_cpp_api POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:fault::fault>
        $<TARGET_FILE_DIR:test_cpp_api>
    )
    add_custom_command(TARGET test_c_api POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
        $<TARGET_FILE:fault::fault>
        $<TARGET_FILE_DIR:test_c_api>
    )
endif()