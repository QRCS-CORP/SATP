cmake_minimum_required(VERSION 3.15)

project(SATP_Complete C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Output dirs
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Download and build QSC
include(FetchContent)
FetchContent_Declare(
  QSC
  GIT_REPOSITORY https://github.com/QRCS-CORP/QSC.git
  GIT_TAG master
)
FetchContent_MakeAvailable(QSC)

# SATP Static Library
file(GLOB_RECURSE SATP_SOURCES "Source/SATP/*.c")
file(GLOB_RECURSE SATP_HEADERS "Source/SATP/include/*.h")

add_library(satp STATIC ${SATP_SOURCES} ${SATP_HEADERS})
target_include_directories(satp PUBLIC "Source/SATP")
target_link_libraries(satp PUBLIC qsc)

# SATP Server
file(GLOB_RECURSE SATP_SERVER_SOURCES "Source/Server/*.c")

add_executable(satp_server ${SATP_SERVER_SOURCES})
target_include_directories(satp_server PRIVATE "Source/Server")
target_link_libraries(satp_server PRIVATE satp)

# SATP Client
file(GLOB_RECURSE SATP_CLIENT_SOURCES "Source/Client/*.c")

add_executable(satp_client ${SATP_CLIENT_SOURCES})
target_include_directories(satp_client PRIVATE "Source/Client")
target_link_libraries(satp_client PRIVATE satp)

# Warnings
foreach(target satp satp_server satp_client)
  if (MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endforeach()
