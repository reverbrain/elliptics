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

add_executable(dnet_cpp_test test.cpp)
target_link_libraries(dnet_cpp_test elliptics_cpp)

add_executable(dnet_cpp_indexes_test indexes-test.cpp)
target_link_libraries(dnet_cpp_indexes_test elliptics_cpp)

install(TARGETS elliptics_cpp
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
