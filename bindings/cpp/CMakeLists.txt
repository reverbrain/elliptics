option(DEVELOPER_BUILD "Enables developer asserts" OFF)

if(DEVELOPER_BUILD)
    add_definitions(-DDEVELOPER_BUILD)
endif(DEVELOPER_BUILD)

find_package(Msgpack REQUIRED)

set(ELLIPTICS_CPP_SRCS
    async_result.cpp
    log.cpp
    node.cpp
    callback_p.h
    callback.cpp
    functional_p.h
    session.cpp
    session_indexes.cpp
    session_indexes.hpp
    exception.cpp
    key.cpp
    )
add_library(elliptics_cpp SHARED ${ELLIPTICS_CPP_SRCS})
set_target_properties(elliptics_cpp PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )
target_link_libraries(elliptics_cpp elliptics_client ${MSGPACK_LIBRARIES} ${Boost_THREAD_LIBRARY})

add_library(test_common STATIC
    ../../example/common.c
    ../../example/config.c
    ../../example/file_backend.c
    ../../example/backends.c
    ../../example/eblob_backend.c
    ../../example/module_backend/core/module_backend_t.c
    ../../example/module_backend/core/dlopen_handle_t.c)
target_link_libraries(test_common dl)

add_executable(dnet_cpp_test test.cpp)
set_target_properties(dnet_cpp_test PROPERTIES
    LINK_FLAGS "-Wl,-rpath,${CMAKE_CURRENT_BINARY_DIR}:${CMAKE_CURRENT_BINARY_DIR}/../:${CMAKE_CURRENT_BINARY_DIR}/../../library:${CMAKE_CURRENT_BINARY_DIR}/../../srw")
target_link_libraries(dnet_cpp_test elliptics elliptics_cocaine elliptics_cpp dl ${Boost_FILESYSTEM_LIBRARY} test_common)

enable_testing()
add_test(NAME test COMMAND dnet_cpp_test)

add_executable(dnet_cpp_indexes_test indexes-test.cpp)
target_link_libraries(dnet_cpp_indexes_test elliptics_cpp)

install(TARGETS elliptics_cpp
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
