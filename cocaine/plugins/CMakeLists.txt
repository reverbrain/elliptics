ADD_LIBRARY(elliptics-extensions MODULE
        storage service module
        ../include/cocaine/framework/services/elliptics.hpp
        ../include/cocaine/idl/elliptics.hpp)

INCLUDE_DIRECTORIES(../include)
TARGET_LINK_LIBRARIES(elliptics-extensions ${ELLIPTICS_LIBRARIES} elliptics_cpp)

SET_TARGET_PROPERTIES(elliptics-extensions PROPERTIES
        PREFIX ""
        SUFFIX ".cocaine-plugin"
)

INSTALL(TARGETS elliptics-extensions
        LIBRARY DESTINATION lib/cocaine
        COMPONENT runtime)
INSTALL(
        DIRECTORY
        ../include/
        DESTINATION include
        COMPONENT development)
