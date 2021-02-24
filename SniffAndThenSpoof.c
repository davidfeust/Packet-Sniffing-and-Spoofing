#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include "packet_heder.h"
#include <netinet/in.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8
void sniffAndSpoof();

int spoof(char src[16], char dst[16]);

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
    spoof(src,dst);
}

int spoof(char src[16], char dst[16]) {
    struct ip iphdr; // IPv4 header
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "This is the spoofed packets!\n";

    unsigned int data_len = strlen(data) + 1;

    //==================
    // IP header
    //==================

    // IP protocol version (4 bits)
    iphdr.ip_v = 4;

    // IP header length (4 bits): Number of 32-bit words in header = 5
    iphdr.ip_hl = IP4_HDRLEN / 4; // not the most correct

    // Type of service (8 bits) - not using, zero it.
    iphdr.ip_tos = 0;

    // Total length of datagram (16 bits): IP header + ICMP header + ICMP data
    iphdr.ip_len = htons(IP4_HDRLEN + ICMP_HDRLEN + data_len);

    // ID sequence number (16 bits): not in use since we do not allow fragmentation
    iphdr.ip_id = 0;

    // Fragmentation bits - we are sending short packets below MTU-size and without
    // fragmentation
    int ip_flags[4];

    // Reserved bit
    ip_flags[0] = 0;

    // "Do not fragment" bit
    ip_flags[1] = 0;

    // "More fragments" bit
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr.ip_off = htons((ip_flags[0] << 15) + (ip_flags[1] << 14)
                         + (ip_flags[2] << 13) + ip_flags[3]);

    // TTL (8 bits): 128 - you can play with it: set to some reasonable number
    iphdr.ip_ttl = 128;

    // Upper protocol (8 bits): ICMP is protocol number 1
    iphdr.ip_p = IPPROTO_ICMP;

    // Source IP
    if (inet_pton(AF_INET, dst, &(iphdr.ip_src)) <= 0) {
        fprintf(stderr, "inet_pton() failed for source-ip with error: %d", errno);
        return -1;
    }

    // Destination IPv
    if (inet_pton(AF_INET, src, &(iphdr.ip_dst)) <= 0) {
        fprintf(stderr, "inet_pton() failed for destination-ip with error: %d", errno);
        return -1;
    }

    //===================
    // ICMP header
    //===================

    // Message Type (8 bits): ICMP_ECHO_REQUEST; ICMP Type: 8 is request, 0 is reply.
    icmphdr.icmp_type = 0;

    // Message Code (8 bits): echo request
    icmphdr.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai

    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;

    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;

    // Combine the packet
    char packet[IP_MAXPACKET];

    // First, IP header.
    memcpy(packet, &iphdr, IP4_HDRLEN);

    // Next, ICMP header
    memcpy((packet + IP4_HDRLEN), &icmphdr, ICMP_HDRLEN);

    // After ICMP header, add the ICMP data.
    memcpy(packet + IP4_HDRLEN + ICMP_HDRLEN, data, data_len);

    // Calculate the ICMP header checksum
//    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet + IP4_HDRLEN), ICMP_HDRLEN + data_len);
//    memcpy(packet + IP4_HDRLEN, &icmphdr, ICMP_HDRLEN);

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;

//     The port is irrelant for Networking and therefore was zeroed.
    dest_in.sin_addr.s_addr = iphdr.ip_dst.s_addr;

    // Create raw socket for IP-RAW (make IP-header by yourself)

    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1) { // IPPROTO_RAW  IPPROTO_ICMP
        fprintf(stderr, "socket() failed with error: %d", errno);
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }

    // Send the packet using sendto() for sending datagrams.
    if (sendto(sock, packet, IP4_HDRLEN + ICMP_HDRLEN + data_len, 0,
               (struct sockaddr *) &dest_in, sizeof(dest_in)) == -1) {
        fprintf(stderr, "sendto() failed with error: %d", errno);
        return -1;
    }
    printf("Sent a spoof packet:\nfrom: %s\nto: %s\n\n", dst, src);

    // Close the raw socket descriptor.
    close(sock);
}

void sniffAndSpoof() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;
    char *dev = "br-df6015565bd5";
    char filter_exp_icmp[] = "icmp";
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
    int compile = pcap_compile(handle, &fp, filter_exp_icmp, 1, net);
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
    pcap_loop(handle, 1, got_packet, NULL);
    pcap_close(handle); //Close the handle
}

int main() {
    while(1){
        sniffAndSpoof();
    }
    return 0;
}
