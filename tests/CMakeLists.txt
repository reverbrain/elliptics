find_package(Boost REQUIRED COMPONENTS iostreams thread regex program_options system filesystem)

set(TEST_LINK_FLAGS "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_BINARY_DIR}/../:${CMAKE_CURRENT_BINARY_DIR}/../library:${CMAKE_CURRENT_BINARY_DIR}/../srw")
set(TEST_PROPERTIES PROPERTIES LINK_FLAGS "${TEST_LINK_FLAGS}")
set(TEST_LIBRARIES elliptics_cpp test_common ${Boost_LIBRARIES})

add_library(test_common SHARED
    ../example/common.c
    ../example/config.c
    ../example/file_backend.c
    ../example/backends.c
    ../example/eblob_backend.c
    ../example/module_backend/core/module_backend_t.c
    ../example/module_backend/core/dlopen_handle_t.c
    test_base.hpp
    test_base.cpp)
set_target_properties(test_common ${TEST_PROPERTIES})
target_link_libraries(test_common elliptics elliptics_cocaine elliptics_cpp dl ${Boost_LIBRARIES})

add_executable(dnet_cpp_test test.cpp)
set_target_properties(dnet_cpp_test ${TEST_PROPERTIES})
target_link_libraries(dnet_cpp_test ${TEST_LIBRARIES})

add_executable(dnet_cpp_cache_test cache_test.cpp)
set_target_properties(dnet_cpp_cache_test ${TEST_PROPERTIES})
target_link_libraries(dnet_cpp_cache_test ${TEST_LIBRARIES})

enable_testing()
set(TEST_ARGUMENTS --report_level=detailed --report_sink=stdout --log_level=warning  --log_sink=stdout)
add_test(NAME test COMMAND dnet_cpp_test ${TEST_ARGUMENTS})
add_test(NAME cache_test COMMAND dnet_cpp_cache_test ${TEST_ARGUMENTS})

add_executable(dnet_cpp_indexes_test indexes-test.cpp)
target_link_libraries(dnet_cpp_indexes_test elliptics_cpp)
