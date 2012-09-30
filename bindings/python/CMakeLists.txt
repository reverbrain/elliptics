find_package(Boost REQUIRED COMPONENTS python)
find_package(PythonLibs REQUIRED)
find_package(PythonInterp REQUIRED)
find_package(PythonExtensionDir REQUIRED)
message(STATUS "Python includes are situated in (${PYTHON_INCLUDE_PATH}, ${PYTHON_INCLUDE_DIRS})")

include_directories(../../include)
include_directories(..)
include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${PYTHON_INCLUDE_DIRS})
add_library(elliptics_python SHARED elliptics_python.cpp)
target_link_libraries(elliptics_python ${Boost_LIBRARIES} ${PYTHON_LIBRARIES} elliptics_cpp)
set_target_properties(elliptics_python PROPERTIES
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )

install(TARGETS elliptics_python
    LIBRARY DESTINATION ${PYTHON_EXTENSION_DIR}
    ARCHIVE DESTINATION ${PYTHON_EXTENSION_DIR}
    BUNDLE DESTINATION library
    )

install(CODE "EXECUTE_PROCESS(
	COMMAND ${PYTHON_EXECUTABLE} setup.py install --prefix=${CMAKE_INSTALL_PATH}
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/bindings/python/
)")
