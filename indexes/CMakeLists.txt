add_library(elliptics_indexes STATIC indexes.cpp)
if(UNIX OR MINGW)
    set_target_properties(elliptics_indexes PROPERTIES COMPILE_FLAGS "-fPIC -std=c++0x")
endif()

find_package(Msgpack REQUIRED)

target_link_libraries(elliptics_indexes ${MSGPACK_LIBRARIES} elliptics_cpp)
