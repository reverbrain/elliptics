# Find Cocaine Native Framework - base for building c++ applications running under the Cocaine.
# https://github.com/cocaine/cocaine-framework-native
#
# This module defines
#  CocaineNative_FOUND - whether the cocaine-framework-native was found
#  CocaineNative_LIBRARIES - it's libraries
#  CocaineNative_INCLUDE_DIRS - it's include paths
#  CocaineNative_CFLAGS - flags to compile with

find_path(CocaineNative_INCLUDE_DIR cocaine/framework/application.hpp)

find_library(CocaineNative_LIBRARY cocaine-framework)

set(CocaineNative_INCLUDE_DIRS "${CocaineNative_INCLUDE_DIR}")
set(CocaineNative_LIBRARIES "${CocaineNative_LIBRARY}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CocaineNative DEFAULT_MSG CocaineNative_LIBRARY CocaineNative_INCLUDE_DIR)

mark_as_advanced(CocaineNative_LIBRARY CocaineNative_INCLUDE_DIR)
