ADD_LIBRARY(elliptics_monitor STATIC
            monitor.cpp
            server.cpp
            statistics.cpp
            histogram.cpp)

if(UNIX OR MINGW)
    set_target_properties(elliptics_monitor PROPERTIES COMPILE_FLAGS "-fPIC")
endif()
target_link_libraries(elliptics_monitor ${Boost_THREAD_LIBRARY})

install(TARGETS elliptics_monitor
    EXPORT EllipticsTargets
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
