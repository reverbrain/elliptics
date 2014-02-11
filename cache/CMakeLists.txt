ADD_LIBRARY(elliptics_cache STATIC
			treap.hpp slru_cache
			cache.cpp)

if(UNIX OR MINGW)
    set_target_properties(elliptics_cache PROPERTIES COMPILE_FLAGS "-fPIC")
endif()
target_link_libraries(elliptics_cache elliptics_indexes)
