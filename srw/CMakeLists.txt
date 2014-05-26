include_directories(../library)

add_library(elliptics_cocaine STATIC srw.cpp)
#set_target_properties(elliptics_cocaine PROPERTIES
#    VERSION ${ELLIPTICS_VERSION}
#    SOVERSION ${ELLIPTICS_VERSION_ABI}
#    )
set_target_properties(elliptics_cocaine PROPERTIES COMPILE_FLAGS "-fPIC")
target_link_libraries(elliptics_cocaine ${ELLIPTICS_LIBRARIES})

#install(TARGETS elliptics_cocaine
#    LIBRARY DESTINATION lib${LIB_SUFFIX}
#    ARCHIVE DESTINATION lib${LIB_SUFFIX}
#    BUNDLE DESTINATION library
#    )
