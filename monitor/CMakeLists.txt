ADD_LIBRARY(elliptics_monitor STATIC
            monitor.cpp
            server.cpp
            statistics.cpp)

if(UNIX OR MINGW)
    target_link_libraries(elliptics_monitor)
endif()
