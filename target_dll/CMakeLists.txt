cmake_minimum_required(VERSION 4.0)
project(target_dll CXX)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE SRCS
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
)

file(GLOB_RECURSE HDRS
    "${CMAKE_SOURCE_DIR}/src/*.hpp"
)

set(ALL_SOURCES
    ${SRCS}
    ${HDRS}
)

add_library(target SHARED ${ALL_SOURCES})

