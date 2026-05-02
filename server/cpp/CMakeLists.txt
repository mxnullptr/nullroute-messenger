cmake_minimum_required(VERSION 3.20)


project(nullroute-server)


# set(CMAKE_BUILD_TYPE "Debug")
# set(CMAKE_BUILD_TYPE "MinSizeRel")
# set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_BUILD_TYPE "RelWithDebInfo")


set(CMAKE_CXX_STANDARD 23)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/build)


execute_process(
  COMMAND git log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
  OUTPUT_VARIABLE GIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)


execute_process(
  COMMAND date +%s
  OUTPUT_VARIABLE BUILD_TIME
  OUTPUT_STRIP_TRAILING_WHITESPACE
)


add_library(dpdk INTERFACE)
target_link_libraries(dpdk INTERFACE -lnuma)


set(Seastar_DIR "/usr/local/lib64/cmake/Seastar" CACHE PATH "Path to Seastar CMake package")


find_package(Seastar REQUIRED)


add_executable(${PROJECT_NAME}
  ./src/${PROJECT_NAME}-app.cc
  ./src/core/core.cc
  ./src/logging/log.cc
  ./src/utils/utils.cc
)


include_directories("${CMAKE_SOURCE_DIR}/src")


target_link_libraries(${PROJECT_NAME} PRIVATE Seastar::seastar)
