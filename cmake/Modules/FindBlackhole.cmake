# Find Eblob
#
# This module defines
#  BLACKHOLE_FOUND - whether the blackhole was found
#  BLACKHOLE_LIBRARIES - blackhole libraries
#  BLACKHOLE_INCLUDE_DIRS - the include path of the blackhole library
#  BLACKHOLE_CFLAGS - blackhole compile flags

if (NOT BLACKHOLE_INCLUDE_DIRS)
    find_path(BLACKHOLE_INCLUDE_DIRS blackhole/attribute.hpp)
endif()

if (NOT BLACKHOLE_LIBRARIES)
	find_library(BLACKHOLE_LIBRARIES NAMES blackhole PATHS ${BLACKHOLE_LIBRARY_DIRS})
endif()

if (NOT BLACKHOLE_CFLAGS)
    set(BLACKHOLE_CFLAGS "-DHAVE_BLACKHOLE=1")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(BLACKHOLE DEFAULT_MSG BLACKHOLE_LIBRARIES BLACKHOLE_INCLUDE_DIRS)
mark_as_advanced(BLACKHOLE_LIBRARIES BLACKHOLE_INCLUDE_DIRS)

