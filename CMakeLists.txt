cmake_minimum_required(VERSION 3.10.0)
project(pcap_sniffer)

SET(CMAKE_CXX_STANDARD 11)
SET(CMAKE_BUILD_TYPE Debug)

# find_package(ZeroMQ REQUIRED)
find_package(catkin REQUIRED COMPONENTS
#   roscpp
#   actionlib
#   actionlib_msgs
#   move_base
#   move_base_msgs
#   roscpp
#   std_msgs
#   std_srvs
#   tf
)

catkin_package(
  INCLUDE_DIRS include
#   CATKIN_DEPENDS roscpp
)

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
