# Find Smack library development version
#
# This module defines
#  SMACK_FOUND - whether the smack library was found
#  SMACK_LIBRARIES - smack library
#  SMACK_INCLUDE_DIRS - the include path of the smack library

if (SMACK_INCLUDE_DIRS AND SMACK_LIBRARIES)
    set (SMACK_FOUND TRUE)
else()
	find_library(SMACK_LIBRARIES NAMES smack PATHS ${SMACK_LIBRARY_DIRS})
    find_path(SMACK_INCLUDE_DIRS NAMES smack/smack.h PATHS)
endif()
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(SMACK DEFAULT_MSG SMACK_LIBRARIES SMACK_INCLUDE_DIRS)
if(SMACK_FOUND)
    set(HAVE_SMACK_SUPPORT 1)
    add_definitions(-DHAVE_SMACK_SUPPORT=1)
endif()
mark_as_advanced(SMACK_INCLUDE_DIRS SMACK_LIBRARIES)
