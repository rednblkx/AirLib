cmake_minimum_required(VERSION 3.10)

# set(CMAKE_BUILD_TYPE Debug)

project(AirLib LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(PkgConfig REQUIRED)
find_package(Boost CONFIG REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
pkg_search_module(AVAHI_DNSSD avahi-compat-libdns_sd)

include_directories(. external dnssd)

add_subdirectory(external/plistcpp)

aux_source_directory(. SRCS)
aux_source_directory(dnssd DNSSD_SRCS)
add_library(AirLib SHARED ${SRCS} ${DNSSD_SRCS})
target_link_libraries(AirLib ${OPENSSL_CRYPTO_LIBRARIES} sodium ${AVAHI_DNSSD_LIBRARIES} avahi-common avahi-client curl PlistCpp)
target_include_directories(AirLib PRIVATE ${AVAHI_DNSSD_INCLUDE_DIRS})
target_compile_definitions(AirLib PRIVATE OPENSSL_API_COMPAT=0x10101000L)
if (Boost_FOUND)
  include_directories(${Boost_INCLUDE_DIRS})
  target_link_libraries(AirLib Boost::system)
else()
  message(FATAL_ERROR "Boost library not found. Please install Boost.")
endif()
