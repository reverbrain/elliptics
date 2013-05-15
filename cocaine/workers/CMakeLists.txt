set(ELLIPTICS_WORKER_SRC
	worker.hpp
	worker.cpp
)

find_package(CocaineNative REQUIRED)

include(../../cmake/Modules/locate_library.cmake)
locate_library(LIBEV "ev++.h" "ev" "libev")

add_executable(elliptics-worker ${ELLIPTICS_WORKER_SRC})

include_directories(${LIBEV_INCLUDE_DIRS} ${CocaineNative_INCLUDE_DIRS})

link_directories(${LIBEV_LIBRARY_DIRS})
target_link_libraries(elliptics-worker ${ELLIPTICS_LIBRARIES} elliptics_cpp ${CocaineNative_LIBRARIES} ev)

set_target_properties(elliptics-worker PROPERTIES
	COMPILE_FLAGS "-std=c++0x"
)

install(TARGETS elliptics-worker
	RUNTIME DESTINATION bin COMPONENT runtime
)
