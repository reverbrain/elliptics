set(ELLIPTICS_CLIENT_SRCS
    check_common.c
    compat.c
    crypto.c
    crypto/sha512.c
    discovery.c
    dnet_common.c
    log.c
    meta.c
    net.c
    node.c
    notify_common.c
    pool.c
    rbtree.c
    trans.c
    )
set(ELLIPTICS_SRCS
    ${ELLIPTICS_CLIENT_SRCS}
    check.c
    dnet.c
    locks.c
    metadb.c
    notify.c
    server.c
    )


add_library(elliptics SHARED ${ELLIPTICS_SRCS})
set_target_properties(elliptics PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    LINKER_LANGUAGE CXX
)
target_link_libraries(elliptics ${ELLIPTICS_LIBRARIES} elliptics_cocaine elliptics_cache)


add_library(elliptics_client SHARED ${ELLIPTICS_CLIENT_SRCS})
set_target_properties(elliptics_client PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )
#target_link_libraries(elliptics_client ${ELLIPTICS_LIBRARIES})
target_link_libraries(elliptics_client ${CMAKE_THREAD_LIBS_INIT})

install(TARGETS elliptics elliptics_client
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
