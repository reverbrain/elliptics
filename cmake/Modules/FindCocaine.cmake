# Find COCAINE engine - engine that makes you fly
# https://github.com/cocaine/cocaine-core
#
# This module defines
#  COCAINE_FOUND - whether the cocaine was found
#  COCAINE_LIBRARIES - cocaine libraries
#  COCAINE_INCLUDE_DIRS - the include path of the cocaine library
#  COCAINE_CFLAGS - flags to compile with

if (NOT COCAINE_INCLUDE_DIRS)
    find_path(COCAINE_INCLUDE_DIRS cocaine/context.hpp)
endif()

if (NOT COCAINE_LIBRARIES)
	find_library(COCAINE_CORE_LIBRARY NAMES cocaine-core PATHS ${COCAINE_LIBRARY_DIRS})
    set(COCAINE_LIBRARIES "${COCAINE_CORE_LIBRARY}" "${COCAINE_COMMON_LIBRARY}")
endif()

if (NOT COCAINE_CFLAGS)
    set(COCAINE_CFLAGS "-DHAVE_COCAINE_SUPPORT=1")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(COCAINE DEFAULT_MSG COCAINE_LIBRARIES COCAINE_INCLUDE_DIRS)

mark_as_advanced(COCAINE_LIBRARIES COCAINE_INCLUDE_DIRS COCAINE_CORE_LIBRARY COCAINE_COMMON_LIBRARY COCAINE_CFLAGS)
