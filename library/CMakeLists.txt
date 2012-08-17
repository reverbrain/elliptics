set(ELLIPTICS_SRCS
    dnet.c
    log.c
    net.c
    server.c
    node.c
    rbtree.c
    trans.c
    compat.c
    notify.c
    notify_common.c
    meta.c
    metadb.c
    crypto.c
    check.c
    check_common.c
    pool.c
    crypto/sha512.c
    locks.c)

set(ELLIPTICS_CLIENT_SRCS
    meta.c
    notify_common.c
    check_common.c
    dnet_common.c
    log.c
    net.c
    node.c
    rbtree.c
    trans.c
    compat.c
    crypto.c
    pool.c
    crypto/sha512.c
    client_stubs.c
    )

include_directories(../include)
add_library(elliptics SHARED ${ELLIPTICS_SRCS})
set_target_properties(elliptics PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )
target_link_libraries(elliptics ${ELLIPTICS_LIBRARIES} elliptics_cocaine elliptics_cache)

add_library(elliptics_static STATIC ${ELLIPTICS_SRCS})
set_target_properties(elliptics_static PROPERTIES
    OUTPUT_NAME elliptics
    )
target_link_libraries(elliptics_static ${ELLIPTICS_LIBRARIES} elliptics_cocaine_static elliptics_cache)

add_library(elliptics_client SHARED ${ELLIPTICS_CLIENT_SRCS})
set_target_properties(elliptics_client PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )
target_link_libraries(elliptics_client ${ELLIPTICS_LIBRARIES})

add_library(elliptics_client_static STATIC ${ELLIPTICS_CLIENT_SRCS})
set_target_properties(elliptics_client_static PROPERTIES
    OUTPUT_NAME elliptics_client
    )
target_link_libraries(elliptics_client_static ${ELLIPTICS_LIBRARIES})

install(TARGETS elliptics elliptics_static elliptics_client elliptics_client_static
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
