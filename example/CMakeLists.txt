include_directories(../include)

add_library(common STATIC common.c)
set(ECOMMON_LIBRARIES common elliptics_client)

set(DNET_IOSERV_SRCS ioserv.c config.c file_backend.c backends.c eblob_backend.c)
set(DNET_IOSERV_LIBRARIES ${ECOMMON_LIBRARIES} elliptics elliptics_cocaine ${SMACK_LIBRARIES})
if(HAVE_SMACK_SUPPORT)
    list(APPEND DNET_IOSERV_SRCS smack_backend.c)
endif()
add_executable(dnet_ioserv ${DNET_IOSERV_SRCS})
target_link_libraries(dnet_ioserv ${DNET_IOSERV_LIBRARIES})

add_executable(dnet_check check.c)
target_link_libraries(dnet_check ${ECOMMON_LIBRARIES})

add_executable(dnet_find find.cpp)
target_link_libraries(dnet_find ${ECOMMON_LIBRARIES} elliptics_cpp)

add_executable(dnet_meta meta.c)
target_link_libraries(dnet_meta ${ECOMMON_LIBRARIES})

add_executable(dnet_ioclient ioclient.c)
target_link_libraries(dnet_ioclient ${ECOMMON_LIBRARIES})

add_executable(dnet_hparser hparser.c)
target_link_libraries(dnet_hparser ${ECOMMON_LIBRARIES})

add_executable(dnet_stat stat.c)
target_link_libraries(dnet_stat ${ECOMMON_LIBRARIES})

add_executable(dnet_notify notify.c)
target_link_libraries(dnet_notify ${ECOMMON_LIBRARIES})

add_executable(dnet_meta_update_groups meta_update_groups.c)
target_link_libraries(dnet_meta_update_groups ${ECOMMON_LIBRARIES})

add_executable(dnet_ids ids.c)
target_link_libraries(dnet_ids "")
