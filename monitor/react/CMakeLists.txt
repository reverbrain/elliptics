add_library(elliptics_react STATIC
	elliptics_react.h
	elliptics_react.hpp
	elliptics_react.cpp
	elliptics_react_actions.h
	elliptics_react_actions.cpp
)

if(UNIX OR MINGW)
	set_target_properties(elliptics_react PROPERTIES COMPILE_FLAGS "-fPIC")
endif()

target_link_libraries(elliptics_react react)

install(TARGETS elliptics_react
	EXPORT EllipticsTargets
	LIBRARY DESTINATION lib${LIB_SUFFIX}
	ARCHIVE DESTINATION lib${LIB_SUFFIX}
	BUNDLE DESTINATION library
	)
