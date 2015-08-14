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
    ../example/backends.c
    ../example/eblob_backend.cpp
    ../example/eblob_backend.c
    test_base.hpp
    test_base.cpp
    test_session.hpp
    test_session.cpp)
set_target_properties(test_common ${TEST_PROPERTIES})
set(TEST_COMMON_LIBRARIES elliptics elliptics_client elliptics_cocaine elliptics_cpp ${Boost_LIBRARIES})
if(WITH_COCAINE)
    list(APPEND TEST_COMMON_LIBRARIES ${CocaineNative_LIBRARIES} ${LIBEV_LIBRARIES})
    list(APPEND TEST_LIBRARIES ${CocaineNative_LIBRARIES} ${LIBEV_LIBRARIES})
endif()
target_link_libraries(test_common ${TEST_COMMON_LIBRARIES})

# add_test_target({target} {test-executable} DEPENDS {required-dependencies})
#
# Defines target for running a test
# Test executable is a target for building a test.
# Dependencies are not only build dependencies but also runtime dependencies.
# (Some tests, for example, launch dnet_ioserv directly,
# so it must be build for those tests to be able to run)
#
function(add_test_target name)
    # Keyword DEPENDS separates test names from dependencies
    list(FIND ARGN "DEPENDS" deps_kw)
    # message("ARGS ${ARGN}")
    # message("KW ${deps_kw}")

    if (NOT ${deps_kw} EQUAL -1)
        set(tests)
        set(deps)

        # this is actually list split operation,
        # argument list gets splitted by DEPENDS into two lists: tests and deps
        set(tests_start 0)
        math(EXPR tests_end "${deps_kw} - 1")
        foreach(i RANGE ${tests_start} ${tests_end})
            # message("INDEX ${i}")
            list(GET ARGN ${i} item)
            list(APPEND tests ${item})
        endforeach()

        math(EXPR deps_start "${deps_kw} + 1")
        list(LENGTH ARGN deps_end)
        math(EXPR deps_end "${deps_end} - 1")
        # message("START ${deps_start}, END ${deps_end}")

        if(NOT ${deps_start} GREATER ${deps_end})
            foreach(i RANGE ${deps_start} ${deps_end})
                # message("INDEX ${i}")
                list(GET ARGN ${i} item)
                list(APPEND deps ${item})
            endforeach()
        endif()

    else()
        set(tests ${ARGN})
        set(deps)

    endif()

    # message("TESTS ${tests}")
    # message("DEPS ${deps}")

    add_custom_target(${name}
        COMMAND ${TEST_ENV} "${PYTHON_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py" "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}" ${tests}
        DEPENDS ${tests} ${deps}
        SOURCES "${PYTHON_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py"
    )
endfunction(add_test_target)

set(TESTS_DEPS dnet_run_servers)

add_executable(dnet_cpp_misc_test test.cpp)
set_target_properties(dnet_cpp_misc_test ${TEST_PROPERTIES})
target_link_libraries(dnet_cpp_misc_test ${TEST_LIBRARIES})
add_test_target(test_misc dnet_cpp_misc_test DEPENDS ${TESTS_DEPS})

add_executable(dnet_cpp_api_test api_test.cpp)
set_target_properties(dnet_cpp_api_test ${TEST_PROPERTIES})
target_link_libraries(dnet_cpp_api_test ${TEST_LIBRARIES})
add_test_target(test_api dnet_cpp_api_test DEPENDS ${TESTS_DEPS})

add_executable(dnet_cpp_cache_test cache_test.cpp)
set_target_properties(dnet_cpp_cache_test ${TEST_PROPERTIES})
target_link_libraries(dnet_cpp_cache_test ${TEST_LIBRARIES})
add_test_target(test_cache dnet_cpp_cache_test DEPENDS ${TESTS_DEPS})

add_executable(dnet_cpp_stats_test stats_test.cpp)
set_target_properties(dnet_cpp_stats_test ${TEST_PROPERTIES})
target_link_libraries(dnet_cpp_stats_test ${TEST_LIBRARIES})
add_test_target(test_stats dnet_cpp_stats_test DEPENDS ${TESTS_DEPS})

add_executable(dnet_cpp_capped_test capped_test.cpp)
set_target_properties(dnet_cpp_capped_test ${TEST_PROPERTIES})
target_link_libraries(dnet_cpp_capped_test ${TEST_LIBRARIES})
add_test_target(test_capped dnet_cpp_capped_test DEPENDS ${TESTS_DEPS})

add_executable(dnet_backends_test backends_test.cpp)
set_target_properties(dnet_backends_test ${TEST_PROPERTIES})
target_link_libraries(dnet_backends_test ${TEST_LIBRARIES})
add_test_target(test_backends dnet_backends_test DEPENDS ${TESTS_DEPS} dnet_ioserv)

add_executable(dnet_weights_test weights_test.cpp)
set_target_properties(dnet_weights_test ${TEST_PROPERTIES})
target_link_libraries(dnet_weights_test ${TEST_LIBRARIES})
add_test_target(test_weights dnet_weights_test DEPENDS ${TESTS_DEPS} dnet_ioserv)

add_executable(dnet_reconnect_test reconnect_test.cpp)
set_target_properties(dnet_reconnect_test ${TEST_PROPERTIES})
target_link_libraries(dnet_reconnect_test ${TEST_LIBRARIES})
add_test_target(test_reconnect dnet_reconnect_test DEPENDS ${TESTS_DEPS} dnet_ioserv)

add_executable(dnet_locks_test locks_test.cpp)
set_target_properties(dnet_locks_test ${TEST_PROPERTIES})
target_link_libraries(dnet_locks_test ${TEST_LIBRARIES})
add_test_target(test_locks dnet_locks_test DEPENDS ${TESTS_DEPS})

add_executable(dnet_crypto_test crypto_test.cpp)
set_target_properties(dnet_crypto_test ${TEST_PROPERTIES})
target_link_libraries(dnet_crypto_test ${TEST_LIBRARIES})
add_test_target(test_crypto dnet_crypto_test DEPENDS ${TESTS_DEPS})

add_executable(dnet_server_send_test server_send.cpp)
set_target_properties(dnet_server_send_test ${TEST_PROPERTIES})
target_link_libraries(dnet_server_send_test ${TEST_LIBRARIES})
add_test_target(test_server_send dnet_server_send_test DEPENDS ${TESTS_DEPS})

#FIXME: add set_target_properties?
add_executable(dnet_cpp_indexes_test indexes-test.cpp)
target_link_libraries(dnet_cpp_indexes_test elliptics_cpp)
#FIXME: is this also a test?
# add_test_target(test_cpp_stats dnet_cpp_stats_test DEPENDS ${TESTS_DEPS})

set(TESTS_LIST
    dnet_cpp_misc_test
    dnet_cpp_api_test
    dnet_cpp_cache_test
    dnet_cpp_stats_test
    dnet_cpp_capped_test
    dnet_backends_test
    dnet_weights_test
    dnet_reconnect_test
    dnet_locks_test
    dnet_crypto_test
    dnet_server_send_test
)

set(RUN_SERVERS_LIBRARIES ${TEST_LIBRARIES})

if(WITH_COCAINE)
    include_directories(../cocaine/include)

    add_executable(dnet_cpp_srw_test srw_test.cpp srw_test.hpp)
    set_target_properties(dnet_cpp_srw_test ${TEST_PROPERTIES})
    target_link_libraries(dnet_cpp_srw_test ${TEST_LIBRARIES} ${CocaineNative_LIBRARIES} ${LIBEV_LIBRARIES})
    add_test_target(test_srw dnet_cpp_srw_test DEPENDS ${TESTS_DEPS} dnet_cpp_srw_test_app elliptics-extensions)

    add_executable(dnet_cpp_srw_test_app srw_test_app.cpp)
    set_target_properties(dnet_cpp_srw_test_app ${TEST_PROPERTIES})
    target_link_libraries(dnet_cpp_srw_test_app elliptics_cpp ${CocaineNative_LIBRARIES} ${Boost_LIBRARIES} ${LIBEV_LIBRARIES})

    add_custom_command(TARGET dnet_cpp_srw_test_app
        POST_BUILD
        COMMAND tar -cf dnet_cpp_srw_test_app.tar dnet_cpp_srw_test_app
        WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    )

    list(APPEND RUN_SERVERS_LIBRARIES ${CocaineNative_LIBRARIES} ${LIBEV_LIBRARIES})
    list(APPEND TESTS_LIST dnet_cpp_srw_test)
    list(APPEND TESTS_DEPS dnet_cpp_srw_test_app)
endif()

add_executable(dnet_run_servers run_servers.cpp)
target_link_libraries(dnet_run_servers ${RUN_SERVERS_LIBRARIES})

add_test_target(test ${TESTS_LIST} DEPENDS ${TESTS_DEPS})

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

set(PYTESTS_FLAGS "-v" "-l" "-x" "--timeout=1200" "--durations=20")
if(NOT WITH_COCAINE)
    list(APPEND PYTESTS_FLAGS "--without-cocaine")
endif()

add_custom_command(TARGET test
    POST_BUILD
    COMMAND virtualenv -p "${PYTHON_EXECUTABLE}" . &&
        . bin/activate &&
        pip install argparse &&
        pip install pytest &&
        pip install pytest-timeout &&
        pip install msgpack-python &&
        export LD_LIBRARY_PATH=.:.. &&
        ${TEST_ENV} py.test ${PYTESTS_FLAGS} ${CMAKE_CURRENT_SOURCE_DIR}/pytests
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/pytests)

install(TARGETS dnet_run_servers
    RUNTIME DESTINATION bin COMPONENT runtime)
