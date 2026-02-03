include(FetchContent)

set(FETCHCONTENT_QUIET FALSE)

if(DOWNLOAD_PCAP OR BUILD_PCAP)
  message("Download pcap...")
  # Fetch libpcap
  FetchContent_Declare(
      libpcap
      SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libpcap"
      GIT_REPOSITORY https://github.com/the-tcpdump-group/libpcap.git
      GIT_TAG master
      GIT_PROGRESS TRUE
  )
  message("Build pcap...")
  FetchContent_MakeAvailable(libpcap)
endif()