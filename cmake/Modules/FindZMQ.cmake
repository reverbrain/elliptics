# Find ØMQ - library with rocket science sockets
#
# This module defines
#  ZMQ_FOUND - whether the ømq was found
#  ZMQ_LIBRARIES - ømq libraries
#  ZMQ_INCLUDE_DIRS - the include path of the ømq library

if (NOT ZMQ_INCLUDE_DIRS)
    find_path(ZMQ_INCLUDE_DIRS zmq.h)
endif()

if (NOT ZMQ_LIBRARIES)
	find_library(ZMQ_LIBRARIES NAMES zmq libzmq PATHS ${ZMQ_LIBRARY_DIRS})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ZMQ DEFAULT_MSG ZMQ_LIBRARIES ZMQ_INCLUDE_DIRS)
mark_as_advanced(ZMQ_LIBRARIES ZMQ_INCLUDE_DIRS)
