ADD_LIBRARY(elliptics_monitor SHARED
            monitor.cpp
            server.cpp
            statistics.cpp
            histogram.cpp
            io_stat_provider.cpp
            react_stat_provider.cpp)

set_target_properties(elliptics_monitor PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    LINKER_LANGUAGE CXX
    )

target_link_libraries(elliptics_monitor ${CMAKE_THREAD_LIBS_INIT} ${Boost_LIBRARIES} reverbrain_react)

install(TARGETS elliptics_monitor
    EXPORT EllipticsTargets
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
