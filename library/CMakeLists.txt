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
    )
set(ELLIPTICS_SRCS
    ${ELLIPTICS_CLIENT_SRCS}
    dnet.c
    locks.c
    notify.c
    server.c
    )


add_library(elliptics_ids STATIC ids.cpp)
if(UNIX OR MINGW)
    set_target_properties(elliptics_ids PROPERTIES COMPILE_FLAGS "-fPIC")
endif()


add_library(elliptics SHARED ${ELLIPTICS_SRCS})
set_target_properties(elliptics PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    LINKER_LANGUAGE CXX
)
target_link_libraries(elliptics ${ELLIPTICS_LIBRARIES} elliptics_cocaine elliptics_cache elliptics_indexes elliptics_ids elliptics_monitor)


add_library(elliptics_client SHARED ${ELLIPTICS_CLIENT_SRCS})
set_target_properties(elliptics_client PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )
#target_link_libraries(elliptics_client ${ELLIPTICS_LIBRARIES})
target_link_libraries(elliptics_client ${CMAKE_THREAD_LIBS_INIT})

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
