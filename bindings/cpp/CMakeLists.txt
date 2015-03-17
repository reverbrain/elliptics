option(DEVELOPER_BUILD "Enables developer asserts" OFF)

if(DEVELOPER_BUILD)
    add_definitions(-DDEVELOPER_BUILD)
endif(DEVELOPER_BUILD)

find_package(Msgpack REQUIRED)

set(ELLIPTICS_CPP_SRCS
    async_result.cpp
    node.cpp
    callback_p.h
    callback.cpp
    functional_p.h
    session.cpp
    session_indexes.cpp
    session_file.cpp
    session_indexes.hpp
    result_entry.cpp
    exception.cpp
    key.cpp
    ../../foreign/cmp/cmp.c
# Added includes for better IDE's experience
    ../../include/elliptics/module_backend.hpp
    ../../include/elliptics/interface.h
    ../../include/elliptics/utils.hpp
    ../../include/elliptics/module_backend.h
    ../../include/elliptics/cppdef.h
    ../../include/elliptics/backends.h
    ../../include/elliptics/session.hpp
    ../../include/elliptics/result_entry.hpp
    ../../include/elliptics/srw.h
    ../../include/elliptics/core.h
    ../../include/elliptics/debug.hpp
    ../../include/elliptics/error.hpp
    ../../include/elliptics/async_result.hpp
    ../../include/elliptics/packet.h
    )
add_library(elliptics_cpp SHARED ${ELLIPTICS_CPP_SRCS})
set_target_properties(elliptics_cpp PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )
target_link_libraries(elliptics_cpp elliptics_client ${MSGPACK_LIBRARIES} ${Boost_THREAD_LIBRARY} ${Boost_FILESYSTEM_LIBRARY} ${Boost_IOSTREAMS_LIBRARY})

install(TARGETS elliptics_cpp
    EXPORT EllipticsTargets
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
