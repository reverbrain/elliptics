# http://www.cmake.org/Wiki/CMake_RPATH_handling#Always_full_RPATH
if (CMAKE_INSTALL_RPATH_USE_LINK_PATH)
    #set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
    message("Set RPATH explicitly to ${CMAKE_INSTALL_RPATH}")
else()
    message("Do not set RPATH exlicitly.")
endif()
