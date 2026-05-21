cmake_minimum_required(VERSION 3.10)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(APServer LANGUAGES CXX)

add_compile_definitions(LINUX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(PkgConfig REQUIRED)
find_package(SDL3 REQUIRED CONFIG REQUIRED COMPONENTS SDL3-shared)

pkg_check_modules(GST REQUIRED gstreamer-1.0>=1.4 gstreamer-sdp-1.0>=1.4 gstreamer-video-1.0>=1.4 gstreamer-app-1.0>=1.4 gstreamer-audio-1.0>=1.4)

add_subdirectory(AirLib)

add_executable(server main.cpp)
target_link_libraries(server SDL3::SDL3 ${GST_LIBRARIES} AirLib)
target_include_directories(server PRIVATE ${GST_INCLUDE_DIRS} AirLib)
