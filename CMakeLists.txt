cmake_minimum_required(VERSION 3.9)
set(CMAKE_CXX_STANDARD 11)

project(sui LANGUAGES C CXX)

option(LIEF_DOC "Build LIEF docs" OFF)
option(LIEF_PYTHON_API "Build LIEF Python API" OFF)
option(LIEF_ENABLE_JSON "Enable JSON-related APIs" OFF)
option(LIEF_EXAMPLES "Build LIEF examples" OFF)
option(LIEF_TESTS "Build LIEF tests" OFF)
if(MSVC)
  set(LIEF_USE_CRT_RELEASE "MT" CACHE STRING "LIEF CRT option")
endif()

add_subdirectory(vendor/lief)

add_library(sui src/sui.h src/sui.cpp)

target_link_libraries(sui PRIVATE LIEF::LIEF)

