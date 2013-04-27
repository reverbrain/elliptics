add_library(common STATIC common.c)
set(ECOMMON_LIBRARIES common elliptics_client)

set(DNET_IOSERV_SRCS ioserv.c config.c file_backend.c backends.c eblob_backend.c)
set(DNET_IOSERV_LIBRARIES ${ECOMMON_LIBRARIES} elliptics elliptics_cocaine dl)

if (HAVE_MODULE_BACKEND_SUPPORT)
    list(APPEND DNET_IOSERV_SRCS
        module_backend/core/module_backend_t.c
	module_backend/core/dlopen_handle_t.c)

    add_subdirectory(module_backend)

    list(APPEND DNET_IOSERV_LIBRARIES dl)
endif()

if(HAVE_LEVELDB_SUPPORT)
    list(APPEND DNET_IOSERV_SRCS leveldb_backend.c)
    list(APPEND DNET_IOSERV_LIBRARIES ${LEVELDB_LIBRARIES})
endif()

add_executable(dnet_ioserv ${DNET_IOSERV_SRCS})
target_link_libraries(dnet_ioserv ${DNET_IOSERV_LIBRARIES})
set_target_properties(dnet_ioserv
	PROPERTIES
	LINKER_LANGUAGE CXX)

# remove NOW
add_executable(dnet_hparser hparser.c)
target_link_libraries(dnet_hparser ${ECOMMON_LIBRARIES})

# remove
add_executable(dnet_check check.c)
target_link_libraries(dnet_check ${ECOMMON_LIBRARIES})

# remove
add_executable(dnet_meta meta.c)
target_link_libraries(dnet_meta ${ECOMMON_LIBRARIES})

# remove
add_executable(dnet_meta_update_groups meta_update_groups.c)
target_link_libraries(dnet_meta_update_groups ${ECOMMON_LIBRARIES})

add_executable(dnet_find find.cpp)
set_target_properties(dnet_find PROPERTIES COMPILE_FLAGS "-std=c++0x")
target_link_libraries(dnet_find ${ECOMMON_LIBRARIES} elliptics_cpp)

add_executable(dnet_ioclient ioclient.cpp)
set_target_properties(dnet_ioclient PROPERTIES COMPILE_FLAGS "-std=c++0x")
target_link_libraries(dnet_ioclient ${ECOMMON_LIBRARIES} elliptics_cpp)

add_executable(dnet_index index.cpp)
set_target_properties(dnet_index PROPERTIES COMPILE_FLAGS "-std=c++0x")
target_link_libraries(dnet_index ${ECOMMON_LIBRARIES} elliptics_cpp)

add_executable(dnet_stat stat.cpp)
set_target_properties(dnet_stat PROPERTIES COMPILE_FLAGS "-std=c++0x")
target_link_libraries(dnet_stat ${ECOMMON_LIBRARIES} elliptics_cpp)

add_executable(dnet_notify notify.cpp)
set_target_properties(dnet_notify PROPERTIES COMPILE_FLAGS "-std=c++0x")
target_link_libraries(dnet_notify ${ECOMMON_LIBRARIES} elliptics_cpp)

add_executable(dnet_ids ids.c)
target_link_libraries(dnet_ids "")

install(TARGETS 
        dnet_ioserv
        dnet_check
        dnet_find
	dnet_meta
	dnet_ioclient
	dnet_index
        dnet_hparser
        dnet_stat
        dnet_notify
        dnet_meta_update_groups
        dnet_ids
    RUNTIME DESTINATION bin COMPONENT runtime)
