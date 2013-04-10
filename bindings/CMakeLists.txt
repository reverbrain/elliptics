# Check for boost
#set(Boost_USE_STATIC_LIBS ON)
#set(Boost_USE_STLPORT ON)
find_package(Boost REQUIRED COMPONENTS iostreams thread regex program_options system)

include_directories(${Boost_INCLUDE_DIRS})
add_definitions(-std=c++0x -Wall -Wextra -Werror)

add_subdirectory(cpp)
if(WITH_PYTHON)
    add_subdirectory(python)
endif()
