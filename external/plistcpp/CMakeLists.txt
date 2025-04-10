cmake_minimum_required(VERSION 3.12)

project(PlistCpp)

set(CMAKE_CXX_STANDARD 20)

find_package(Boost CONFIG REQUIRED COMPONENTS system)

aux_source_directory(. SRCS)

add_library(PlistCpp SHARED ${SRCS})

target_include_directories(PlistCpp PUBLIC ${Boost_INCLUDE_DIRS})

target_link_libraries(PlistCpp PUBLIC ${Boost_LIBRARIES})