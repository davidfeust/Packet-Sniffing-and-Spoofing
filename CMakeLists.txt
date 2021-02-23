cmake_minimum_required(VERSION 3.17)
project(PniffingAndSpoofing C)

set(CMAKE_C_STANDARD 99)

add_executable(Pcap pcap_sniffer.c)