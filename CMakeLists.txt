cmake_minimum_required(VERSION 3.12)
project(natExplorer)

set(CMAKE_CXX_STANDARD 14)
add_executable(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/main.cpp
                                ${CMAKE_SOURCE_DIR}/main.h)
include_directories(${CMAKE_SOURCE_DIR})