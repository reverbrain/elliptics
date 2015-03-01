cmake_minimum_required (VERSION 2.6 FATAL_ERROR)
cmake_policy (VERSION 2.6.0)

#set(CMAKE_SKIP_RPATH OFF)
#set(CMAKE_SKIP_BUILD_RPATH  OFF)
#set(CMAKE_SKIP_INSTALL_RPATH ON)
#set(CMAKE_BUILD_WITH_INSTALL_RPATH ON)

project (elliptics)
FILE (READ "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog" DEBCHANGELOG)

string(REGEX MATCH "([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)" DEBFULLVERSION "${DEBCHANGELOG}")
STRING(REGEX MATCH "([0-9]+\\.[0-9]+)" ELLIPTICS_VERSION_ABI "${DEBFULLVERSION}")
STRING(REGEX MATCH "([0-9]+\\.[0-9]+$)" ELLIPTICS_VERSION_MINOR "${DEBFULLVERSION}")
string(REPLACE "." ";" VERSION_LIST ${DEBFULLVERSION})
list(GET VERSION_LIST 0 ELLIPTICS_VERSION_0)
list(GET VERSION_LIST 1 ELLIPTICS_VERSION_1)
list(GET VERSION_LIST 2 ELLIPTICS_VERSION_2)
list(GET VERSION_LIST 3 ELLIPTICS_VERSION_3)

add_definitions(-DCONFIG_ELLIPTICS_VERSION_0=${ELLIPTICS_VERSION_0})
add_definitions(-DCONFIG_ELLIPTICS_VERSION_1=${ELLIPTICS_VERSION_1})
add_definitions(-DCONFIG_ELLIPTICS_VERSION_2=${ELLIPTICS_VERSION_2})
add_definitions(-DCONFIG_ELLIPTICS_VERSION_3=${ELLIPTICS_VERSION_3})

option(WITH_PYTHON "Build python bindings" ON)
option(WITH_COCAINE "Build with cocaine support" ON)
option(WITH_EXAMPLES "Build example applications" ON)
option(HAVE_MODULE_BACKEND_SUPPORT "Build ioserv with shared library backend support" ON)

set(ELLIPTICS_VERSION "${ELLIPTICS_VERSION_ABI}.${ELLIPTICS_VERSION_MINOR}")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x -std=gnu++0x")
include(CheckLargefile)
include(CheckAtomic)
include(CheckSendfile)
include(CheckIoprio)
include(TestBigEndian)
include(CheckProcStats)
include(CreateStdint)
include(FixRpath)

find_path(BLACKHOLE_INCLUDE_DIRS NAMES "blackhole/attribute.hpp" PATH_SUFFIXES)
if (NOT BLACKHOLE_INCLUDE_DIRS)
	message(FATAL_ERROR "Blackhole development files have not been found")
endif()
include_directories(${BLACKHOLE_INCLUDE_DIRS})

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/monitor)

# Set id_size
if (NOT ID_SIZE)
    set(ID_SIZE 64)
endif()
add_definitions(-DCONFIG_ID_SIZE=${ID_SIZE})

# Test endianness
test_big_endian(HAVE_BIG_ENDIAN)
if(HAVE_BIG_ENDIAN)
    add_definitions(-DBYTEORDER=4321)
    add_definitions(-DWORDS_BIGENDIAN=1)
else()
    add_definitions(-DBYTEORDER=1234)
endif()

if (UNIX OR MINGW)
    add_definitions(-W -Wall -Wextra -fstack-protector-all -fno-strict-aliasing -g)
endif()

# Check for threads
if (UNIX AND BSD)
    set(CMAKE_THREAD_LIBS -pthread)
    set(CMAKE_USE_PTHREADS ON)
    set(CMAKE_EXE_LINKER_FLAGS -pthread -Wl,--as-needed)
endif()

set(CMAKE_THREAD_PREFER_PTHREAD ON)
find_package(Threads REQUIRED)

if(WITH_COCAINE)
    # Find some cocaine
    find_package(Cocaine REQUIRED)
    include_directories(${COCAINE_INCLUDE_DIRS})
    add_definitions(${COCAINE_CFLAGS})
endif()

# Find eblob
find_package(Eblob REQUIRED)
include_directories(${EBLOB_INCLUDE_DIRS})

if (HAVE_MODULE_BACKEND_SUPPORT)
    add_definitions(-DHAVE_MODULE_BACKEND_SUPPORT=1)
    add_subdirectory(example/module_backend)
endif()

# Handystats instrumentation
option(WITH_STATS "Build with runtime statistics gathering" ON)

if (WITH_STATS)
    find_package(Handystats REQUIRED)
    include_directories(${HANDYSTATS_INCLUDE_DIRS})
    add_definitions(${HANDYSTATS_CFLAGS})
else()
    # Handystats symbols are spilled across many source files,
    # so even if we do want to disable handystats instrumentation,
    # handystats headers still needed to set macros to empty stubs.
    find_package(Handystats)
    if (HANDYSTATS_FOUND)
        add_definitions(${HANDYSTATS_CFLAGS})
        add_definitions("-DHANDYSTATS_DISABLE=1")
    endif()
endif()

option(WITH_DOXYGEN "Generate documentation by Doxygen" ON)

if(WITH_DOXYGEN)
    message("-- Checking for Doxygen...")
    find_package(Doxygen)
endif()

# GoLD does no overlinking
find_package(Boost REQUIRED COMPONENTS iostreams thread regex program_options system filesystem)
message(STATUS "Boost information:")
message(STATUS "  Boost_INCLUDE_DIRS: ${Boost_INCLUDE_DIRS}")
message(STATUS "  Boost_LIBRARY_DIRS: ${Boost_LIBRARY_DIRS}")
message(STATUS "  Boost_LIBRARIES: ${Boost_LIBRARIES}")
include_directories(${Boost_INCLUDE_DIRS})
link_directories(${Boost_LIBRARY_DIRS})

# Collect all libraries together
set(ELLIPTICS_LIBRARIES
    ${SENDFILE_LIBRARIES}
    ${Boost_LIBRARIES}
    ${EBLOB_LIBRARIES}
    ${COCAINE_LIBRARIES}
    ${CMAKE_THREAD_LIBS_INIT}
    )

# Build parts
add_subdirectory(srw)
add_subdirectory(cache)
add_subdirectory(indexes)
add_subdirectory(library)
add_subdirectory(bindings)
add_subdirectory(monitor)
add_subdirectory(tests)
if(WITH_EXAMPLES)
    add_subdirectory(example)
endif()
if(WITH_COCAINE)
    add_subdirectory(cocaine/plugins)
endif()

install(FILES
        include/elliptics/core.h
        include/elliptics/interface.h
        include/elliptics/packet.h
        include/elliptics/srw.h
        include/elliptics/async_result.hpp
        include/elliptics/cppdef.h
        include/elliptics/debug.hpp
        include/elliptics/error.hpp
        include/elliptics/result_entry.hpp
        include/elliptics/session.hpp
        include/elliptics/timer.hpp
        include/elliptics/utils.hpp
        include/elliptics/backends.h
        include/elliptics/module_backend.h
        include/elliptics/module_backend.hpp
        include/elliptics/logger.hpp
        DESTINATION include/elliptics/
        )

set(INSTALL_INCLUDE_DIR "${CMAKE_INSTALL_PREFIX}/include")
set(INSTALL_LIBRARY_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}")

export(TARGETS elliptics_client elliptics_cpp
    FILE "${PROJECT_BINARY_DIR}/EllipticsTargets.cmake")

#export(PACKAGE Elliptics)

configure_file(cmake/EllipticsConfig.cmake.in
                "${PROJECT_BINARY_DIR}/cmake/EllipticsConfig.cmake"
                @ONLY)
configure_file(cmake/EllipticsConfigVersion.cmake.in
                "${PROJECT_BINARY_DIR}/cmake/EllipticsConfigVersion.cmake"
                @ONLY)

install(FILES
    "${PROJECT_BINARY_DIR}/cmake/EllipticsConfig.cmake"
    "${PROJECT_BINARY_DIR}/cmake/EllipticsConfigVersion.cmake"
    DESTINATION share/elliptics/cmake)
install(EXPORT EllipticsTargets DESTINATION share/elliptics/cmake)

FILE(GLOB man_pages "man/*")
install(FILES ${man_pages} DESTINATION share/man/man1)

if(DOXYGEN_FOUND)
    add_subdirectory(doc)
    set(DOC_TARGET "doc")
    configure_file(doc/Doxyfile.in ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile @ONLY)
    configure_file(doc/DoxygenLayout.xml.in ${CMAKE_CURRENT_BINARY_DIR}/DoxygenLayout.xml @ONLY)
    add_custom_target(${DOC_TARGET}
        ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
        COMMENT "Building documentation"
        SOURCE doc/Doxyfile.in doc/DoxygenLayout.xml)

#	install( DIRECTORY
#		${CMAKE_CURRENT_BINARY_DIR}/doc/html
#		${CMAKE_CURRENT_BINARY_DIR}/doc/qch
#		DESTINATION share/elliptics/doc
#        )
endif()

