find_package(Boost REQUIRED COMPONENTS iostreams thread regex program_options system filesystem)

set(TEST_LINK_FLAGS "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_BINARY_DIR}/../:${CMAKE_CURRENT_BINARY_DIR}/../library:${CMAKE_CURRENT_BINARY_DIR}/../srw:${CMAKE_CURRENT_BINARY_DIR}/../bindings/cpp:${CMAKE_CURRENT_BINARY_DIR}/../monitor")
set(TEST_PROPERTIES PROPERTIES LINK_FLAGS "${TEST_LINK_FLAGS}" LINKER_LANGUAGE CXX)
set(TEST_LIBRARIES  test_common elliptics elliptics_client elliptics_cpp ${Boost_LIBRARIES})

add_definitions(
    -DCOCAINE_CONFIG_PATH="${CMAKE_CURRENT_SOURCE_DIR}/cocaine.conf"
    -DCOCAINE_PLUGINS_PATH="${CMAKE_CURRENT_BINARY_DIR}/../cocaine/plugins"
    -DCOCAINE_TEST_APP="${CMAKE_CURRENT_BINARY_DIR}/dnet_cpp_srw_test_app.tar"
)

if(WITH_COCAINE)
    add_definitions("-DHAVE_COCAINE")
endif()

add_library(test_common SHARED
    ../example/common.c
    ../example/config.cpp
    ../example/file_backend.c
    ../example/backends.c
    ../example/eblob_backend.c
    ../example/module_backend/core/module_backend_t.c
    ../example/module_backend/core/dlopen_handle_t.c
    test_base.hpp
    test_base.cpp)
set_target_properties(test_common ${TEST_PROPERTIES})
target_link_libraries(test_common elliptics elliptics_client elliptics_cocaine elliptics_cpp dl ${Boost_LIBRARIES})

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


set(PYTESTS_FLAGS  --source_dir="${CMAKE_CURRENT_SOURCE_DIR}" --binary_dir="${CMAKE_CURRENT_BINARY_DIR}")
#if(NOT WITH_COCAINE)
    list(APPEND PYTESTS_FLAGS "--without-cocaine")
#endif()

set(RUN_SERVERS_LIBRARIES ${TEST_LIBRARIES})

if(WITH_COCAINE)
    include(../cmake/Modules/locate_library.cmake)
    LOCATE_LIBRARY(LIBEV "ev++.h" "ev" "libev")

    find_package(CocaineNative REQUIRED)
    include_directories(${CocaineNative_INCLUDE_DIRS} ${LIBEV_INCLUDE_DIRS})

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
set_target_properties(dnet_run_servers ${TEST_PROPERTIES})
target_link_libraries(dnet_run_servers ${RUN_SERVERS_LIBRARIES})

set(TESTS_LIST dnet_cpp_test dnet_cpp_cache_test dnet_cpp_capped_test dnet_cpp_api_test)
set(TESTS_DEPS ${TESTS_LIST})

add_custom_target(test
    COMMAND "${PYTHON_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py" "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}" ${TESTS_LIST}
    DEPENDS ${TESTS_DEPS}
    SOURCES "${PYTHON_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/run_tests.py")

add_custom_command(TARGET test
    POST_BUILD
    COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/pytests/elliptics
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/../bindings/python/core.so* pytests/elliptics/
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/../bindings/cpp/libelliptics_cpp.so* pytests/
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/../library/libelliptics*.so* pytests/
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/../srw/libelliptics_cocaine.so* pytests/
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/../monitor/libelliptics_monitor.so* pytests/
    COMMAND cp ${CMAKE_CURRENT_BINARY_DIR}/../example/dnet_ioserv pytests/
    COMMAND cp ${CMAKE_SOURCE_DIR}/bindings/python/src/* pytests/elliptics/
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

SET(ENV{LD_LIBRARY_PATH} ".")

add_custom_command(TARGET test
    POST_BUILD
    COMMAND virtualenv -p "${PYTHON_EXECUTABLE}" . &&
        . bin/activate &&
        pip install pytest &&
        export LD_LIBRARY_PATH=.:.. &&
        py.test ${CMAKE_CURRENT_SOURCE_DIR}/pytests ${PYTESTS_FLAGS}
    #COMMAND rm -fr *
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/pytests)

add_executable(dnet_cpp_indexes_test indexes-test.cpp)
target_link_libraries(dnet_cpp_indexes_test elliptics_cpp)
