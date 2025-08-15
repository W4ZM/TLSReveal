cmake_minimum_required(VERSION 4.0)
project(TLSMessageReveal CXX)

# remove old dll hpp and cpp files
file(REMOVE "${CMAKE_SOURCE_DIR}/src/dll.cpp" "${CMAKE_SOURCE_DIR}/src/dll.hpp")

# build the dll
message(STATUS "[ BUILDING DLL ]")
execute_process(
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/dll
  COMMAND cmd.exe /c build.cmd
  VERBATIM
)


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

add_executable(Loader ${ALL_SOURCES})

set_target_properties(Loader PROPERTIES VS_GLOBAL_CharacterSet "MultiByte")

set_target_properties(Loader PROPERTIES
    LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
)