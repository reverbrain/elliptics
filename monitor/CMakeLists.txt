set(REACT_HEADERS
    react/elliptics_react.h
    react/elliptics_react.hpp
    react/elliptics_react_actions.h
    )

set(REACT_SOURCES
    react/elliptics_react.cpp
    react/elliptics_react_actions.cpp
    )

ADD_LIBRARY(elliptics_monitor SHARED
            monitor.cpp
            server.cpp
            statistics.cpp
            histogram.cpp
            io_stat_provider.cpp
            react_stat_provider.cpp
            ${REACT_HEADERS}
            ${REACT_SOURCES}
            backends_stat_provider.cpp
            procfs_provider.cpp
    )

set_target_properties(elliptics_monitor PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    LINKER_LANGUAGE CXX
    )

target_link_libraries(elliptics_monitor ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES} react elliptics_client)

install(TARGETS elliptics_monitor
    EXPORT EllipticsTargets
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
