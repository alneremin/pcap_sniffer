cmake_minimum_required(VERSION 3.10.0)
project(pcap_sniffer)

SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE Debug)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(PCAP)

if(PCAP_FOUND)
  message("Pcap is found (PCAP_INCLUDE_DIR==${PCAP_INCLUDE_DIR})")
else()
  set(BUILD_PCAP TRUE)
endif()

add_subdirectory(external)

include_directories(
  "include/pcap_sniffer"
#   ${ZeroMQ_INCLUDE_DIRS}
)

add_executable(pcap_sniffer
  src/main.cpp
  src/pcap_sniffer.cpp
)

target_link_libraries(pcap_sniffer
  PUBLIC
  PRIVATE
  pcap
)
