# Find the msgpack library
# http://msgpack.org

include(CheckCXXSourceCompiles)

if (NOT MSGPACK_LIBRARIES)
    find_library(MSGPACK_LIBRARIES NAMES msgpack HINTS ${MSGPACK_LIBRARY_DIR})
endif()
if (NOT MSGPACK_INCLUDE_DIRS)
    find_path(MSGPACK_INCLUDE_DIRS NAMES msgpack.hpp)
endif()
set(CMAKE_REQUIRED_LIBRARIES ${MSGPACK_LIBRARIES})
set(CMAKE_REQUIRED_INCLUDES ${MSGPACK_INCLUDE_DIRS})
check_cxx_source_compiles("#include <msgpack.hpp>
int main()
{
    msgpack::sbuffer buffer;
    return 0;
}" HAVE_MSGPACK_SUPPORT)
unset(CMAKE_REQUIRED_LIBRARIES)
unset(CMAKE_REQUIRED_INCLUDES)
if (HAVE_MSGPACK_SUPPORT)
    add_definitions(-DHAVE_MSGPACK_SUPPORT=1)
endif()
message(STATUS "Msgpack found: ${HAVE_MSGPACK_SUPPORT}")
mark_as_advanced(MSGPACK_LIBRARY_DIR MSGPACK_INCLUDE_DIRS)
