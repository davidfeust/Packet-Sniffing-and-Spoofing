#include <stdio.h>
#include <pcap/pcap.h>
#include "packet_heder.h"
#include <netinet/in.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
//    Decapsulation of the packet in order to get from it the data that we want
    ip_h *ipH = (ip_h *) (packet + SIZE_ETHERNET);
    unsigned int size_ip = IP_HL(ipH) * 4;

    if (size_ip < 20) {
        printf("\t*Invalid IP header length: %u bytes\n\n", size_ip);
        return;
    }

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    printf("**Got Packet**\n");
    inet_ntop(AF_INET, &(ipH->ip_src.s_addr), src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipH->ip_dst.s_addr), dst, INET_ADDRSTRLEN);
    printf("host: %s \ndest: %s\n\n", src, dst);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

// Open live pcap session on NIC with name eth3
    handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 1000, errbuf);

// Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); //Close the handle
    return 0;
}

/*
 * for testing run from host:
 * ping 8.8.8.8 -c 1
 */