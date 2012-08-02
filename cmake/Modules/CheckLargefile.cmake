# Check whether large files are supported

include(CheckCSourceCompiles)

if (UNIX OR MINGW)
    SET(CMAKE_REQUIRED_DEFINITIONS -Werror-implicit-function-declaration)
endif()
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_LARGEFILE64_SOURCE=1)

check_c_source_compiles("#include <fcntl.h>
#include <sys/stat.h>
int main()
{
    int fd = open(\".\", O_RDONLY | O_LARGEFILE);
    return 0;
}
" HAVE_LARGEFILE_SUPPORT)

if (HAVE_LARGEFILE_SUPPORT)
    add_definitions(-DHAVE_LARGEFILE_SUPPORT=1 -D_LARGEFILE64_SOURCE=1)
endif()

unset(CMAKE_REQUIRED_DEFINITIONS)
message(STATUS "Large file support found: ${HAVE_LARGEFILE_SUPPORT}")
