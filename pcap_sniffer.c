#include <stdio.h>
#include <pcap/pcap.h>
#include "packet_heder.h"
#include <netinet/in.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    ethernet_h *ethernetH = (ethernet_h *) (packet);
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

/*
    tcp_h *tcpH = (tcp_h*)(packet + SIZE_ETHERNET + size_ip);
    unsigned int size_tcp = TH_OFF(tcpH)*4;
    if (size_tcp < 20) {

        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    unsigned char *payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
*/
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;
    char filter_exp[] = "IPPROTO_ICMP"; //"ip proto icmp";
    bpf_u_int32 net = 0;

// Open live pcap session on NIC with name eth3
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

// Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); //Close the handle
    return 0;
}