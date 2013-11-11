add_library(elliptics_indexes STATIC indexes.cpp local_session.h local_session.cpp)
if(UNIX OR MINGW)
    set_target_properties(elliptics_indexes PROPERTIES COMPILE_FLAGS "-fPIC")
endif()

find_package(Msgpack REQUIRED)

target_link_libraries(elliptics_indexes ${MSGPACK_LIBRARIES} elliptics_cpp)
