cmake_minimum_required(VERSION 4.0)
project(x64-dll-manual-mapper CXX)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# remove old dll files
file(REMOVE "${CMAKE_SOURCE_DIR}/src/dll.cpp" "${CMAKE_SOURCE_DIR}/src/dll.hpp")

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

file(GLOB_RECURSE SCRIPT
    "${CMAKE_SOURCE_DIR}/cmake/*.cmake"
)

add_subdirectory(${PROJECT_SOURCE_DIR}/target_dll)

add_executable(mapper ${ALL_SOURCES})

set_target_properties(mapper PROPERTIES VS_GLOBAL_CharacterSet "MultiByte")

add_dependencies(mapper target)

# to create bytes array from target.dll
add_custom_command(
  TARGET mapper
  PRE_BUILD
  COMMAND ${CMAKE_COMMAND} -D target_dll="$<TARGET_FILE:target>" -D source_dir="${CMAKE_SOURCE_DIR}/src" -P ${SCRIPT} 
  COMMENT "--- Running ${SCRIPT}"
)