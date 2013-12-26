ADD_LIBRARY(elliptics_monitor STATIC
            monitor.cpp
            server.cpp
            statistics.cpp
            histogram.cpp)

if(UNIX OR MINGW)
    set_target_properties(elliptics_monitor PROPERTIES COMPILE_FLAGS "-fPIC")
endif()
