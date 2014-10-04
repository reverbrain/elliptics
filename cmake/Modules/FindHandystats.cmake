# Find HANDYSTATS library
#
# This module defines
#  HANDYSTATS_FOUND - whether the handystats was found
#  HANDYSTATS_LIBRARY - handystats libraries
#  HANDYSTATS_INCLUDE_DIRS - the include path of the handystats library
#  HANDYSTATS_CFLAGS - flags to compile with

find_path(HANDYSTATS_INCLUDE_DIRS handystats/core.hpp)

find_library(HANDYSTATS_LIBRARY handystats)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Handystats DEFAULT_MSG HANDYSTATS_LIBRARY HANDYSTATS_INCLUDE_DIRS)

if (HANDYSTATS_FOUND)
    set(HANDYSTATS_CFLAGS "-DHAVE_HANDYSTATS=1")
endif()

#mark_as_advanced(HANDYSTATS_LIBRARY HANDYSTATS_INCLUDE_DIRS HANDYSTATS_CFLAGS)
