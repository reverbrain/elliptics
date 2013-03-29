include_directories(../../include)

option(DEVELOPER_BUILD "Enables developer asserts" OFF)

if(DEVELOPER_BUILD)
    add_definitions(-DDEVELOPER_BUILD)
endif(DEVELOPER_BUILD)

find_package(Msgpack REQUIRED)

set(ELLIPTICS_CPP_SRCS
    log.cpp
    node.cpp
    session.cpp
    session_indexes.cpp
    callback.cpp
    exception.cpp
    key.cpp
    )
add_library(elliptics_cpp SHARED ${ELLIPTICS_CPP_SRCS})
set_target_properties(elliptics_cpp PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )
target_link_libraries(elliptics_cpp elliptics_client ${MSGPACK_LIBRARIES} ${Boost_THREAD_LIBRARY})

add_library(elliptics_cpp_static STATIC ${ELLIPTICS_CPP_SRCS})
set_target_properties(elliptics_cpp_static PROPERTIES
    OUTPUT_NAME elliptics_cpp
    )

add_executable(dnet_cpp_test test.cpp)
target_link_libraries(dnet_cpp_test elliptics_cpp)

add_executable(dnet_cpp_indexes_test indexes-test.cpp)
target_link_libraries(dnet_cpp_indexes_test elliptics_cpp)

install(TARGETS elliptics_cpp elliptics_cpp_static
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
