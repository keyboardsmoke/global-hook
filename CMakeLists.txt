cmake_minimum_required(VERSION 3.2)
project(GlobalHook CXX)

set (CMAKE_CXX_STANDARD 14)

include_directories("${CMAKE_SOURCE_DIR}/capstone/include/")
include_directories("${CMAKE_SOURCE_DIR}/keystone/include/keystone/")

set(CMAKE_CXX_COMPILER "clang++-3.9")

if (THUMB)
	set(CMAKE_CXX_FLAGS "-mthumb")
endif()

#message(AUTHOR_WARNING ${LIBCAPSTONE_LIBRARIES})

add_executable(GlobalHook main.cpp detour.cpp detour.hpp)

if (WIN32)
	target_link_libraries(GlobalHook "${CMAKE_CURRENT_SOURCE_DIR}/capstone/MinSizeRel/capstone.lib" "${CMAKE_CURRENT_SOURCE_DIR}/keystone/llvm/lib/MinSizeRel/keystone.lib")
else()
	target_link_libraries(GlobalHook "${CMAKE_CURRENT_SOURCE_DIR}/capstone/libcapstone.a" "${CMAKE_CURRENT_SOURCE_DIR}/keystone/build-lib/llvm/lib/libkeystone.a")
endif()