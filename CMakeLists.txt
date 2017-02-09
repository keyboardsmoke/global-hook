cmake_minimum_required(VERSION 3.2)
project(ArmHook CXX)

set (CMAKE_CXX_STANDARD 14)

include_directories("${CMAKE_SOURCE_DIR}/capstone/include/")
include_directories("${CMAKE_SOURCE_DIR}/keystone/include/keystone/")

set(CMAKE_CXX_COMPILER "clang++-3.9")

if (THUMB)
	set(CMAKE_CXX_FLAGS "-mthumb")
endif()

#message(AUTHOR_WARNING ${LIBCAPSTONE_LIBRARIES})

add_executable(ArmHook main.cpp detour.cpp)
target_link_libraries(ArmHook "${CMAKE_CURRENT_SOURCE_DIR}/capstone/libcapstone.a" "${CMAKE_CURRENT_SOURCE_DIR}/keystone/build-lib/llvm/lib/libkeystone.a")