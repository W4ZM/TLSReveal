cmake_minimum_required(VERSION 4.0)
project(keyauth_example CXX)

# set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


file(GLOB_RECURSE SRCS
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
)

file(GLOB_RECURSE HDRS
    "${CMAKE_SOURCE_DIR}/src/*.hpp"
    "${CMAKE_SOURCE_DIR}/src/*.h"
)

set(ALL_SOURCES
    ${SRCS}
    ${HDRS}
)

add_executable(crackme ${ALL_SOURCES})
set_target_properties(crackme PROPERTIES VS_GLOBAL_CharacterSet "MultiByte")
target_link_libraries(crackme ${CMAKE_SOURCE_DIR}/src/library_x64.lib)