

#include <stdio.h>
#include <pcap/pcap.h>
#include "packet_heder.h"
#include <netinet/in.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <stdlib.h>


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
    printf("host: %s \ndest: %s\n", src, dst);

    tcp_h *tcpH = (tcp_h *) (packet + SIZE_ETHERNET + size_ip);
    unsigned int size_tcp = TH_OFF(tcpH) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    unsigned char *data = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
    unsigned int size_data = ntohs(ipH->ip_len) - (size_ip + size_tcp);
    if (size_data != 0) {
        printf("the data is:\n");
        for (int i = 0; i < size_data; ++i) {
            printf("%c", data[i]);
        }
    }
    printf("\n\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;
    char *dev = "br-df6015565bd5";
    char filter_exp_tcp[] = "tcp";
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;

// Open live pcap session on NIC with name eth3
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(-1);
    }
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
// Step 2: Compile filter_exp into BPF psuedo-code
    int compile = pcap_compile(handle, &fp, filter_exp_tcp, 1, net);
    if (compile == -1) {
        fprintf(stderr, "Couldn't compile device %s: %s\n", dev, errbuf);
        exit(-1);
    }
    int setfilter = pcap_setfilter(handle, &fp);
    if (setfilter == -1) {
        fprintf(stderr, "setfilter dose not work properly %s\n", errbuf);
        exit(-1);
    }
// Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle); //Close the handle
    return 0;
}