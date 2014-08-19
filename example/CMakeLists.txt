add_library(elliptics_common STATIC common.c)
set(ECOMMON_LIBRARIES elliptics_common elliptics_client)
if(UNIX OR MINGW)
    set_target_properties(elliptics_common PROPERTIES COMPILE_FLAGS "-fPIC")
endif()

set(DNET_IOSERV_SRCS ioserv.c)
set(DNET_IOSERV_LIBRARIES ${ECOMMON_LIBRARIES} elliptics elliptics_cocaine dl)

add_executable(dnet_ioserv ${DNET_IOSERV_SRCS})
target_link_libraries(dnet_ioserv ${DNET_IOSERV_LIBRARIES})
set_target_properties(dnet_ioserv
    PROPERTIES
    LINKER_LANGUAGE CXX)

add_executable(dnet_find find.cpp)
target_link_libraries(dnet_find ${ECOMMON_LIBRARIES} elliptics_cpp)

add_executable(dnet_index_perf index_perf.cpp)
target_link_libraries(dnet_index_perf ${ECOMMON_LIBRARIES} elliptics_cpp boost_program_options)

add_executable(dnet_ioclient ioclient.cpp)
target_link_libraries(dnet_ioclient ${ECOMMON_LIBRARIES} elliptics_cpp)

add_executable(dnet_index index.cpp)
target_link_libraries(dnet_index ${ECOMMON_LIBRARIES} elliptics_cpp)

add_executable(dnet_notify notify.cpp)
target_link_libraries(dnet_notify ${ECOMMON_LIBRARIES} elliptics_cpp)

add_executable(dnet_ids ids.c)
target_link_libraries(dnet_ids "")

add_executable(iterate iterate.cpp)
target_link_libraries(iterate ${ECOMMON_LIBRARIES} elliptics_cpp boost_program_options)

install(TARGETS
        dnet_ioserv
        dnet_find
        dnet_ioclient
        dnet_index
        dnet_notify
        dnet_ids
    RUNTIME DESTINATION bin COMPONENT runtime)
