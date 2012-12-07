include_directories(../../include)

set(ELLIPTICS_CPP_SRCS
    log.cpp
    node.cpp
    session.cpp
    callback.cpp
    exception.cpp
    key.cpp
    )
add_library(elliptics_cpp SHARED ${ELLIPTICS_CPP_SRCS})
set_target_properties(elliptics_cpp PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )
target_link_libraries(elliptics_cpp elliptics_client ${Boost_THREAD_LIBRARY})

add_library(elliptics_cpp_static STATIC ${ELLIPTICS_CPP_SRCS})
set_target_properties(elliptics_cpp_static PROPERTIES
    OUTPUT_NAME elliptics_cpp
    )

add_executable(dnet_cpp_test test.cpp)
target_link_libraries(dnet_cpp_test elliptics_cpp)

install(TARGETS elliptics_cpp elliptics_cpp_static
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
