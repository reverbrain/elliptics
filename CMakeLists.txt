cmake_minimum_required (VERSION 2.6 FATAL_ERROR)
cmake_policy (VERSION 2.6.0)

project (elliptics)
set(ELLIPTICS_VERSION_ABI "2")
set(ELLIPTICS_VERSION_MINOR "14.1")

set(ELLIPTICS_VERSION "${ELLIPTICS_VERSION_ABI}.${ELLIPTICS_VERSION_MINOR}")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
include(CheckLargefile)
include(CheckAtomic)
include(CheckSendfile)
include(CheckIoprio)
include(TestBigEndian)
include(CheckProcStats)

# Set id_size
if (NOT ID_SIZE)
    set(ID_SIZE 64)
endif()
add_definitions(-DCONFIG_ID_SIZE=${ID_SIZE})

# Test endianess
test_big_endian(HAVE_BIG_ENDIAN)
if(HAVE_BIG_ENDIAN)
    add_definitions(-DBYTEORDER=4321)
    add_definitions(-DWORDS_BIGENDIAN=1)
else()
    add_definitions(-DBYTEORDER=1234)
endif()

if (UNIX OR MINGW)
    add_definitions(-W -Wall -Wextra -fstack-protector-all -fno-strict-aliasing)
endif()

# Check for threads
if (UNIX AND BSD)
    set(CMAKE_THREAD_LIBS -pthread)
    set(CMAKE_USE_PTHREADS ON)
    set(CMAKE_EXE_LINKER_FLAGS -pthread)
endif()

set(CMAKE_THREAD_PREFER_PTHREAD ON)
find_package(Threads REQUIRED)

# Check for boost
#set(Boost_USE_STATIC_LIBS ON)
#set(Boost_USE_STLPORT ON)
find_package(Boost REQUIRED COMPONENTS iostreams thread regex python program_options system filesystem)
include_directories(${Boost_INCLUDE_DIRS})

# Find some cocaine
find_package(Cocaine REQUIRED)
include_directories(${COCAINE_INCLUDE_DIRS})
add_definitions(${COCAINE_CFLAGS})

# Find ømq
find_package(ZMQ REQUIRED)
include_directories(${ZMQ_INCLUDE_DIRS})

# Find eblob
find_package(Eblob REQUIRED)
include_directories(${EBLOB_INCLUDE_DIRS})

# Find msgpack
find_package(Msgpack REQUIRED)
include_directories(${MSGPACK_INCLUDE_DIRS})

# Collect all libraries together
set(ELLIPTICS_LIBRARIES ${MSGPACK_LIBRARIES} ${SENDFILE_LIBRARIES} ${Boost_LIBRARIES} ${EBLOB_LIBRARIES} ${ZMQ_LIBRARIES} ${COCAINE_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

# Build parts
add_subdirectory(srw)
#add_subdirectory(example)
#add_subdirectory(bindings)
add_subdirectory(library)

install(FILES
        include/elliptics/core.h
        include/elliptics/cppdef.h
        include/elliptics/interface.h
        include/elliptics/packet.h
        include/elliptics/srw.h
    DESTINATION include/elliptics/
    )
