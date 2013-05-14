set(ELLIPTICS_WORKER_SRC
	worker.hpp
	worker.cpp
)

add_executable(elliptics-worker ${ELLIPTICS_WORKER_SRC})

target_link_libraries(elliptics-worker ${ELLIPTICS_LIBRARIES} elliptics_cpp -lcocaine-framework -lev)

set_target_properties(elliptics-worker PROPERTIES
	COMPILE_FLAGS "-std=c++0x"
)

install(TARGETS elliptics-worker
	RUNTIME DESTINATION bin COMPONENT runtime
)
