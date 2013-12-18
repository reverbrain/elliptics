project(rift)
cmake_minimum_required(VERSION 2.6)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
add_definitions("-DNO_SERVER")

find_package(Boost REQUIRED COMPONENTS iostreams thread regex program_options system filesystem)
find_package(Elliptics REQUIRED)

include_directories(${ELLIPTICS_INCLUDE_DIRS})

add_executable(dnet_cpp_test ../test.cpp ../test_base.cpp)
target_link_libraries(dnet_cpp_test ${Boost_LIBRARIES} ${ELLIPTICS_LIBRARIES})
