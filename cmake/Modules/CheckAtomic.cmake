# Check whether libatomic or __sync are supported
# Sets variables:
#  HAVE_ATOMIC_SUPPORT - whether atomic support is available
#  ATOMIC_LIBRARIES - libraries to link with
#  ATOMIC_INCLUDE_DIRS - include path
#  HAVE_SYNC_ATOMIC_SUPPORT - whether __sync support is available

include(CheckCSourceCompiles)

find_library(ATOMIC_LIBRARIES NAMES atomic HINTS ${ATOMIC_LIBRARY_DIR})
set(CMAKE_REQUIRED_LIBRARIES ${ATOMIC_LIBRARIES})
set(CMAKE_REQUIRED_INCLUDES ${ATOMIC_INCLUDE_DIRS})
check_c_source_compiles("#include <atomic/atomic.h>
int main()
{
    atomic_t a;
    atomic_set(&a, 1);
    atomic_inc(&a);
    return 0;
}" HAVE_ATOMIC_SUPPORT)
if (HAVE_ATOMIC_SUPPORT)
    add_definitions(-DHAVE_LIBATOMIC_SUPPORT=1)
endif()
unset(CMAKE_REQUIRED_LIBRARIES)
unset(CMAKE_REQUIRED_INCLUDES)

check_c_source_compiles("int main()
{
    long var;
    __sync_add_and_fetch(&var, 1);
    return 0;
}" HAVE_SYNC_ATOMIC_SUPPORT)
if (HAVE_SYNC_ATOMIC_SUPPORT)
    add_definitions(-DHAVE_SYNC_ATOMIC_SUPPORT=1)
endif()

message(STATUS "Libatomic support: ${HAVE_ATOMIC_SUPPORT}")
message(STATUS "__sync support: ${HAVE_SYNC_ATOMIC_SUPPORT}")
mark_as_advanced(ATOMIC_LIBRARY_DIR ATOMIC_INCLUDE_DIRS)
