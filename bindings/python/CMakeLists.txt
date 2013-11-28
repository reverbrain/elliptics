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
    async_result.cpp
    result_entry.cpp
    elliptics_time.cpp
    elliptics_io_attr.cpp
    elliptics_session.cpp
    )

add_library(core_python SHARED ${ELLIPTICS_PYTHON_SRCS})
target_link_libraries(core_python ${Boost_LIBRARIES} ${PYTHON_LIBRARIES} elliptics_cpp)
set_target_properties(core_python PROPERTIES
    PREFIX ""
    OUTPUT_NAME "core"
    VERSION ${ELLIPTICS_VERSION}
    SOVERSION ${ELLIPTICS_VERSION_ABI}
    )

install(TARGETS core_python
    LIBRARY DESTINATION ${PYTHON_EXTENSION_DIR}/elliptics
    ARCHIVE DESTINATION ${PYTHON_EXTENSION_DIR}/elliptics
    BUNDLE DESTINATION library
    )

install(CODE "EXECUTE_PROCESS(
	COMMAND ${PYTHON_EXECUTABLE} setup.py install --prefix=$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/
)")
