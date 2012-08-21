# Check supported methods to gather system statistics

if(EXISTS "/proc/loadavg" AND EXISTS "/proc/meminfo")
    set(HAVE_PROC_STAT 1)
    add_definitions(-DHAVE_PROC_STAT=1)
    message(STATUS "System supports procfs statistics")
    return()
endif()

include(CheckCSourceRuns)
if (UNIX OR MINGW)
    SET(CMAKE_REQUIRED_DEFINITIONS -Werror-implicit-function-declaration)
endif()
check_c_source_runs("#include <stdio.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
int main()
{
    struct loadavg la;
    size_t sz = sizeof(la);
    return sysctlbyname(\"vm.loadavg\", &la, &sz, NULL, 0);
}" HAVE_SYSCTL_STAT)
unset(CMAKE_REQUIRED_DEFINITIONS)
if (HAVE_SYSCTL_STAT)
    add_definitions(-DHAVE_SYSCTL_STAT=1)
    message(STATUS "System supports sysctl statistics")
endif()
