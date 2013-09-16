find_package(Boost REQUIRED COMPONENTS python)
find_package(PythonLibs REQUIRED)
find_package(PythonInterp REQUIRED)
find_package(PythonExtensionDir REQUIRED)
message(STATUS "Python includes are situated in (${PYTHON_INCLUDE_PATH}, ${PYTHON_INCLUDE_DIRS})")

include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${PYTHON_INCLUDE_DIRS})

set(ELLIPTICS_PYTHON_SRCS
    elliptics_python.cpp
    elliptics_id.cpp
    )

add_library(elliptics_python SHARED ${ELLIPTICS_PYTHON_SRCS} elliptics_python.cpp)
target_link_libraries(elliptics_python ${Boost_LIBRARIES} ${PYTHON_LIBRARIES} elliptics_cpp)
set_target_properties(elliptics_python PROPERTIES
    PREFIX ""
    OUTPUT_NAME "elliptics"
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )

install(TARGETS elliptics_python
    LIBRARY DESTINATION ${PYTHON_EXTENSION_DIR}
    ARCHIVE DESTINATION ${PYTHON_EXTENSION_DIR}
    BUNDLE DESTINATION library
    )

install(CODE "EXECUTE_PROCESS(
	COMMAND ${PYTHON_EXECUTABLE} setup.py install --prefix=${CMAKE_INSTALL_PREFIX}
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/bindings/python/
)")
