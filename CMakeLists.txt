cmake_minimum_required(VERSION 3.17)
project(SniffingAndSpoofing C)
set(CMAKE_C_STANDARD 99)

include(FindPCAP.cmake)

add_executable(Pcap pcap_sniffer.c packet_heder.h)


#SET(CMAKE_MODULE_PATH "/home/david/CLionProjects/SniffingAndSpoofing")
SET(CMAKE_MODULE_PATH "/home/david/CLionProjects/Packet-Sniffing-and-Spoofing")

find_package(PCAP REQUIRED)
target_link_libraries(Pcap ${PCAP_LIBRARY})