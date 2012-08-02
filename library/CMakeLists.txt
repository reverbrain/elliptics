set(ELLIPTICS_SRCS
    dnet.c
    log.c
    net.c
    node.c
    rbtree.c
    trans.c
    compat.c
    notify.c
    meta.c
    metadb.c
    crypto.c
    check.c
    pool.c
    crypto/sha512.c
    locks.c)

include_directories(../include)
add_library(elliptics SHARED ${ELLIPTICS_SRCS})
set_target_properties(elliptics PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )
target_link_libraries(elliptics ${ELLIPTICS_LIBRARIES} elliptics_cocaine)

add_library(elliptics_static STATIC ${ELLIPTICS_SRCS})
set_target_properties(elliptics_static PROPERTIES
    OUTPUT_NAME elliptics
    )
target_link_libraries(elliptics_static ${ELLIPTICS_LIBRARIES} elliptics_cocaine_static)

install(TARGETS elliptics elliptics_static
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
