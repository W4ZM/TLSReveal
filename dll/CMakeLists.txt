cmake_minimum_required(VERSION 4.0)
project(dll CXX)

# crt static linking
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

# hex bytes generator script
file(GLOB_RECURSE SCRIPT
    "${CMAKE_SOURCE_DIR}/../cmake/*.cmake"
)

add_library(MyDll SHARED ${ALL_SOURCES})
set_target_properties(MyDll PROPERTIES VS_GLOBAL_CharacterSet "MultiByte")

# run script after building dll
add_custom_command(
  TARGET MyDll
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -D target_dll="$<TARGET_FILE:MyDll>" -D source_dir="${CMAKE_SOURCE_DIR}/../src" -P ${SCRIPT} 
  COMMENT "-- [ GENERATING DLL HEX BYTES ]"
)

