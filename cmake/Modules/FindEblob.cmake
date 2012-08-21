# Find Eblob
#
# This module defines
#  EBLOB_FOUND - whether the eblob was found
#  EBLOB_LIBRARIES - eblob libraries
#  EBLOB_INCLUDE_DIRS - the include path of the eblob library
#  EBLOB_CFLAGS - eblob compile flags

if (NOT EBLOB_INCLUDE_DIRS)
    find_path(EBLOB_INCLUDE_DIRS eblob/blob.h)
endif()

if (NOT EBLOB_LIBRARIES)
	find_library(EBLOB_LIBRARIES NAMES eblob PATHS ${EBLOB_LIBRARY_DIRS})
endif()

if (NOT EBLOB_CFLAGS)
    set(EBLOB_CFLAGS "-DHAVE_EBLOB=1")
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(EBLOB DEFAULT_MSG EBLOB_LIBRARIES EBLOB_INCLUDE_DIRS)
mark_as_advanced(EBLOB_LIBRARIES EBLOB_INCLUDE_DIRS)

