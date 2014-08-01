# Check for boost
#set(Boost_USE_STATIC_LIBS ON)
#set(Boost_USE_STLPORT ON)
add_definitions(-Wall -Wextra)

add_subdirectory(cpp)
if(WITH_PYTHON)
    add_subdirectory(python)
endif()
