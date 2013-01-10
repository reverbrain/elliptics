include_directories(../include)
include_directories(../library)

add_definitions("-std=c++0x")

add_library(elliptics_cocaine SHARED srw.cpp)
set_target_properties(elliptics_cocaine PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )
target_link_libraries(elliptics_cocaine ${ELLIPTICS_LIBRARIES})
add_library(elliptics_cocaine_static STATIC srw.cpp)
set_target_properties(elliptics_cocaine_static PROPERTIES
    OUTPUT_NAME elliptics_cocaine
    )
target_link_libraries(elliptics_cocaine_static ${ELLIPTICS_LIBRARIES})

install(TARGETS elliptics_cocaine elliptics_cocaine_static
    LIBRARY DESTINATION lib${LIB_SUFFIX}
    ARCHIVE DESTINATION lib${LIB_SUFFIX}
    BUNDLE DESTINATION library
    )
