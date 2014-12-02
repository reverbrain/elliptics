find_package(Boost REQUIRED COMPONENTS iostreams thread regex program_options system filesystem)

set(TEST_LIBRARY_PATH "${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_BINARY_DIR}/../:${CMAKE_CURRENT_BINARY_DIR}/../library:${CMAKE_CURRENT_BINARY_DIR}/../srw:${CMAKE_CURRENT_BINARY_DIR}/../bindings/cpp:${CMAKE_CURRENT_BINARY_DIR}/../monitor")
set(TEST_LINK_FLAGS "-Wl,-rpath,${TEST_LIBRARY_PATH}")
set(TEST_PROPERTIES PROPERTIES LINK_FLAGS "${TEST_LINK_FLAGS}" LINKER_LANGUAGE CXX)
set(TEST_LIBRARIES  test_common elliptics elliptics_client elliptics_cpp ${Boost_LIBRARIES})
set(TEST_IOSERV_PATH "${CMAKE_CURRENT_BINARY_DIR}/../example/dnet_ioserv")
set(TEST_ENV
    TEST_COCAINE_CONFIG=${CMAKE_CURRENT_SOURCE_DIR}/cocaine.conf
    TEST_COCAINE_PLUGINS=${CMAKE_CURRENT_BINARY_DIR}/../cocaine/plugins
    TEST_COCAINE_APP=${CMAKE_CURRENT_BINARY_DIR}/dnet_cpp_srw_test_app.tar
    TEST_IOSERV_PATH=${TEST_IOSERV_PATH}
    LD_LIBRARY_PATH=${TEST_LIBRARY_PATH}:$ENV{LD_LIBRARY_PATH}
)

if(WITH_COCAINE)
    add_definitions("-DHAVE_COCAINE")

    include(../cmake/Modules/locate_library.cmake)
    LOCATE_LIBRARY(LIBEV "ev++.h" "ev" "libev")

    find_package(CocaineNative REQUIRED)
    include_directories(${CocaineNative_INCLUDE_DIRS} ${LIBEV_INCLUDE_DIRS})
endif()

add_library(test_common STATIC
    ../example/common.c
    ../example/config.cpp
    ../example/config_impl.cpp
    ../example/file_backend.c
    ../example/backends.c
    ../example/eblob_backend.c
    ../example/module_backend/core/module_backend_t.c
    ../example/module_backend/core/dlopen_handle_t.c
    test_base.hpp
    test_base.cpp)
set_target_properties(test_common ${TEST_PROPERTIES})
set(TEST_COMMON_LIBRARIES elliptics elliptics_client elliptics_cocaine elliptics_cpp dl ${Boost_LIBRARIES})
if(WITH_COCAINE)
    list(APPEND TEST_COMMON_LIBRARIES ${CocaineNative_LIBRARIES} ${LIBEV_LIBRARIES})
    list(APPEND TEST_LIBRARIES ${CocaineNative_LIBRARIES} ${LIBEV_LIBRARIES})
endif()
target_link_libraries(test_common ${TEST_COMMON_LIBRARIES})

add_executable(dnet_cpp_test test.cpp)
set_target_properties(dnet_cpp_test ${TEST_PROPERTIES})
target_link_libraries(dnet_cpp_test ${TEST_LIBRARIES})

add_executable(dnet_cpp_api_test api_test.cpp)
set_target_properties(dnet_cpp_api_test ${TEST_PROPERTIES})
target_link_libraries(dnet_cpp_api_test ${TEST_LIBRARIES})

add_executable(dnet_cpp_cache_test cache_test.cpp)
set_target_properties(dnet_cpp_cache_test ${TEST_PROPERTIES})
target_link_libraries(dnet_cpp_cache_test ${TEST_LIBRARIES})

add_executable(dnet_cpp_capped_test capped_test.cpp)
set_target_properties(dnet_cpp_capped_test ${TEST_PROPERTIES})
target_link_libraries(dnet_cpp_capped_test ${TEST_LIBRARIES})

add_executable(dnet_backends_test backends_test.cpp)
set_target_properties(dnet_backends_test ${TEST_PROPERTIES})
target_link_libraries(dnet_backends_test ${TEST_LIBRARIES})


set(PYTESTS_FLAGS "-l" "-x" "--timeout=300" "--durations=10")
if(NOT WITH_COCAINE)
    list(APPEND PYTESTS_FLAGS "--without-cocaine")
endif()

set(RUN_SERVERS_LIBRARIES ${TEST_LIBRARIES})

set(TESTS_LIST dnet_cpp_test dnet_cpp_cache_test dnet_cpp_capped_test dnet_backends_test dnet_cpp_api_test)
set(TESTS_DEPS ${TESTS_LIST})

if(WITH_COCAINE)
    add_executable(dnet_cpp_srw_test srw_test.cpp srw_test.hpp)
    set_target_properties(dnet_cpp_srw_test ${TEST_PROPERTIES})
    target_link_libraries(dnet_cpp_srw_test ${TEST_LIBRARIES} ${CocaineNative_LIBRARIES} ${LIBEV_LIBRARIES})

    add_executable(dnet_cpp_srw_test_app srw_test_app.cpp)
    set_target_properties(dnet_cpp_srw_test_app ${TEST_PROPERTIES})
    target_link_libraries(dnet_cpp_srw_test_app elliptics_cpp ${CocaineNative_LIBRARIES} ${Boost_LIBRARIES} ${LIBEV_LIBRARIES})

    add_custom_command(TARGET dnet_cpp_srw_test_app
        POST_BUILD
        COMMAND tar -cf dnet_cpp_srw_test_app.tar dnet_cpp_srw_test_app
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

        list(APPEND TESTS_LIST dnet_cpp_srw_test)
        list(APPEND TESTS_DEPS dnet_cpp_srw_test dnet_cpp_srw_test_app)

    list(APPEND RUN_SERVERS_LIBRARIES ${CocaineNative_LIBRARIES} ${LIBEV_LIBRARIES})
endif()

add_executable(dnet_run_servers run_servers.cpp)
target_link_libraries(dnet_run_servers ${RUN_SERVERS_LIBRARIES})

list(APPEND TESTS_DEPS dnet_run_servers)

add_custom_target(test
    COMMAND ${TEST_ENV} "${PYTHON_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py" "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}" ${TESTS_LIST}
    DEPENDS ${TESTS_DEPS}
    SOURCES "${PYTHON_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py")

add_custom_command(TARGET test
    POST_BUILD
    COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/pytests/elliptics
    COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/pytests/elliptics_recovery
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/../bindings/python/core.so* pytests/elliptics/
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/../bindings/cpp/libelliptics_cpp.so* pytests/
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/../*/libelliptics*.so* pytests/
    COMMAND cp ${CMAKE_SOURCE_DIR}/bindings/python/src/* pytests/elliptics/
    COMMAND cp -r ${CMAKE_SOURCE_DIR}/recovery/elliptics_recovery/* pytests/elliptics_recovery/
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)
add_custom_command(TARGET test
    POST_BUILD
    COMMAND virtualenv -p "${PYTHON_EXECUTABLE}" . &&
        . bin/activate &&
        pip install pytest &&
        pip install pytest-timeout &&
        pip install msgpack-python &&
        export LD_LIBRARY_PATH=.:.. &&
        ${TEST_ENV} py.test ${PYTESTS_FLAGS} ${CMAKE_CURRENT_SOURCE_DIR}/pytests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/pytests)

add_executable(dnet_cpp_indexes_test indexes-test.cpp)
target_link_libraries(dnet_cpp_indexes_test elliptics_cpp)

install(TARGETS dnet_run_servers
    RUNTIME DESTINATION bin COMPONENT runtime)
