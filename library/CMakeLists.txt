set(ELLIPTICS_CLIENT_SRCS
    compat.c
    crypto.c
    crypto/sha512.c
    dnet_common.c
    log.c
    net.c
    net.cpp
    node.c
    notify_common.c
    pool.c
    rbtree.c
    trans.c
    tests.c
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
    ../example/config.hpp
    ../example/config.cpp
    ../example/config_impl.cpp
    ../example/file_backend.cpp
    ../example/file_backend.c
    ../example/backends.c
    ../example/eblob_backend.cpp
    ../example/eblob_backend.c
    )

if (HAVE_MODULE_BACKEND_SUPPORT)
    list(APPEND ELLIPTICS_SRCS
        ../example/module_backend/core/module_backend_t.c
        ../example/module_backend/core/dlopen_handle_t.c)

    list(APPEND ELLIPTICS_LIBRARIES dl)
endif()

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
target_link_libraries(elliptics_client ${CMAKE_THREAD_LIBS_INIT} ${Boost_THREAD_LIBRARY} ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})
if (WITH_STATS)
    target_link_libraries(elliptics_client ${HANDYSTATS_LIBRARY})
endif()

add_library(elliptics SHARED ${ELLIPTICS_SRCS})
set_target_properties(elliptics PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    LINKER_LANGUAGE CXX
    )
target_link_libraries(elliptics ${ELLIPTICS_LIBRARIES} ${EBLOB_LIBRARIES} elliptics_common elliptics_cocaine elliptics_cache elliptics_indexes elliptics_ids elliptics_monitor elliptics_client elliptics_cpp)

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
