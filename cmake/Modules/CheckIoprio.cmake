# Check whether ioprio is supported

include(CheckCSourceCompiles)

if (UNIX OR MINGW)
    SET(CMAKE_REQUIRED_DEFINITIONS -Werror-implicit-function-declaration)
endif()

check_c_source_compiles("#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>
int main()
{
    syscall(SYS_ioprio_set, 1, getpid(), 3);
    int prio = syscall(SYS_ioprio_get, 1, getpid());
    return 0;
}" HAVE_IOPRIO_SUPPORT)
unset(CMAKE_REQUIRED_DEFINITIONS)

if(HAVE_IOPRIO_SUPPORT)
    add_definitions(-DHAVE_IOPRIO_SUPPORT=1)
endif()
message(STATUS "Ioprio support: ${HAVE_IOPRIO_SUPPORT}")
