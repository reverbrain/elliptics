set(ELLIPTICS_CLIENT_SRCS
    compat.c
    crypto.c
    crypto/sha512.c
    discovery.c
    dnet_common.c
    log.c
    net.c
    node.c
    notify_common.c
    pool.c
    rbtree.c
    trans.c
    common.cpp
    ../bindings/cpp/logger.cpp
    )
set(ELLIPTICS_SRCS
    dnet.c
    locks.c
    notify.c
    server.c
    route.cpp
    backend.cpp
    )

add_library(elliptics_ids STATIC ids.cpp)
if(UNIX OR MINGW)
    set_target_properties(elliptics_ids PROPERTIES COMPILE_FLAGS "-fPIC")
endif()

add_library(elliptics_client SHARED ${ELLIPTICS_CLIENT_SRCS})
set_target_properties(elliptics_client PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    LINKER_LANGUAGE CXX
    )
target_link_libraries(elliptics_client ${CMAKE_THREAD_LIBS_INIT} ${Boost_THREAD_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})

add_library(elliptics SHARED ${ELLIPTICS_SRCS})
set_target_properties(elliptics PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    LINKER_LANGUAGE CXX
    )
target_link_libraries(elliptics ${ELLIPTICS_LIBRARIES} elliptics_cocaine elliptics_cache elliptics_indexes elliptics_ids elliptics_monitor elliptics_client elliptics_cpp)

install(TARGETS elliptics
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )

install(TARGETS elliptics_client
    EXPORT EllipticsTargets
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
