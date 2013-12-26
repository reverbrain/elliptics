ADD_LIBRARY(elliptics_monitor SHARED
            monitor.cpp
            server.cpp
            statistics.cpp
            histogram.cpp)

if(UNIX OR MINGW)
    set_target_properties(elliptics_cache PROPERTIES COMPILE_FLAGS "-fPIC")
endif()
