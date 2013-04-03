ADD_LIBRARY(elliptics-extensions MODULE storage module)

TARGET_LINK_LIBRARIES(elliptics-extensions ${ELLIPTICS_LIBRARIES})

SET_TARGET_PROPERTIES(elliptics-extensions PROPERTIES
	PREFIX ""
	SUFFIX ".cocaine-plugin"
        COMPILE_FLAGS "-std=c++0x"
)

INSTALL(TARGETS elliptics-extensions
	LIBRARY DESTINATION lib/cocaine
	COMPONENT runtime)
