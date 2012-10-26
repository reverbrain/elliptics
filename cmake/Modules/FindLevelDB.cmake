# Find LevelDB library development version
#
# This module defines
#  LEVELDB_FOUND - whether the LevelDB library was found
#  LEVELDB_LIBRARIES - LevelDB library
#  LEVELDB_INCLUDE_DIRS - the include path of the LevelDB library

if (LEVELDB_INCLUDE_DIRS AND LEVELDB_LIBRARIES)
    set (LEVELDB_FOUND TRUE)
else()
	find_library(LEVELDB_LIBRARIES NAMES leveldb PATHS ${LEVELDB_LIBRARY_DIRS})
    find_path(LEVELDB_INCLUDE_DIRS NAMES leveldb/c.h PATHS)
endif()
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LEVELDB DEFAULT_MSG LEVELDB_LIBRARIES LEVELDB_INCLUDE_DIRS)
if(LEVELDB_FOUND)
    set(HAVE_LEVELDB_SUPPORT 1)
    add_definitions(-DHAVE_LEVELDB_SUPPORT=1)
endif()
mark_as_advanced(LEVELDB_INCLUDE_DIRS LEVELDB_LIBRARIES)
