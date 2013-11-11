set(SOURCES
	cpp/honest_command_handler_adaptee.cpp
	cpp/registration.cpp
)
add_library(elliptics_module_backend_cpp SHARED ${SOURCES})
target_link_libraries(elliptics_module_backend_cpp elliptics elliptics_cpp)
set_target_properties(elliptics_module_backend_cpp PROPERTIES VERSION ${ELLIPTICS_VERSION} SOVERSION ${ELLIPTICS_VERSION_ABI})
install(TARGETS elliptics_module_backend_cpp LIBRARY DESTINATION lib${LIB_SUFFIX})

set(TEST_SOURCES
	test/test_uncomplicated_handler.cpp
)
add_library(test_uncomplicated_handler MODULE ${TEST_SOURCES})
target_link_libraries(test_uncomplicated_handler elliptics_module_backend_cpp)
set_target_properties(test_uncomplicated_handler PROPERTIES PREFIX "")
