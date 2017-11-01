/**
 * hijack_telnet.c
 */

#include "sniffer.h"
#include "netlog.h"
#include "netlib.h"

#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include <string.h>
#include <pcap.h>
#include <stdbool.h>

#define INFO_BUF_SIZE 256
#define INFO_BUFFER 128


pcap_t* handler;
libnet_t* netcons;


void leavesniffer(int sig) {
	struct pcap_stat stats;
    if (pcap_stats(handler, &stats) >= 0) {
		    
    }   
    pcap_close(handler);
    libnet_destroy(netcons);
    exit(0);
}


void parse_pkt(struct pcap_pkthdr* header, const u_char* data) {
    struct ip_hdr* ipheader;
    struct tcp_hdr* tcpheader;
    struct icmp_hdr* icmpheader;
    struct ethernet_hdr* ethheader;
    u_char* payload;

    bool has_ip_header = true;
    bool has_tcp_header = false;
    bool has_payload = true;
    bool has_icmp = false;
    // caplen is the length of the packet we captured
    // len is the actual length the packet is supposed to be
    // printf("%ld %ld\n", header->caplen, header->len);

    int ip_size;
    int tcp_size;
    int payload_size;


    ethheader = (struct ethernet_hdr*) data;
    ipheader = (struct ip_hdr*) (data + ETHER_HDR_LEN);
    ip_size = ipheader->ip_hlen * 4;
    if (ip_size < 20) {
        has_ip_header = false;
    }
    if (ipheader->ip_protocol == IP_ICMP) {
        icmpheader = (struct icmp_hdr*) (data + ip_size + ETHER_HDR_LEN);
        has_icmp = true;
    } else if (ipheader->ip_protocol == IP_TCP) {
        has_tcp_header = true;
    }

    tcpheader = (struct tcp_hdr*) (data + ETHER_HDR_LEN + ip_size);
    tcp_size = (tcpheader->tcp_off) * 4;
    if (tcp_size < 20) {
        //has_tcp_header = false;
        printf("TCP: Size %d\n", tcp_size);
        printf("TCP: Offset %x", tcpheader->tcp_off);
    }

	payload = (u_char*) (data + ETHER_HDR_LEN + ip_size + tcp_size);
    payload_size = ntohs(ipheader->ip_len) - (ip_size + tcp_size);
    if (payload_size <= 0) {
        has_payload = false;
    }


    log_ethernet(ethheader);
    if (has_ip_header)  log_ip(ipheader);
    if (has_tcp_header) log_tcp(tcpheader, payload_size);
    if (has_payload && has_tcp_header)    log_payload(payload, payload_size);
    if (has_icmp)       log_icmp(icmpheader);
    printf("\n");

}



void main_loop(pcap_t* pd) {
    struct pcap_pkthdr *pktHeader;
    const u_char *pktData;
    int status;
    status = pcap_next_ex(pd, &pktHeader, &pktData);

    switch (status) {
        case 1:
            parse_pkt(pktHeader, pktData);
            main_loop(pd);
            break;
        case 0:
            main_loop(pd);
            break;
        case -1:
            printf("libpcap error in mainloop() - exiting...");
            leavesniffer(1);
            break;
        case -2:
            printf("Breakloop called - exiting...");
            leavesniffer(0);
            break;
        default:
            printf("Recieved unrecognized status in mainloop()...");
            leavesniffer(1);
            break;
    }
    return;
}




int main (int argc, char** argv) {
	if (argc < 3 || argc > 4) {
		printf("Usage: ");
		printf("hijack_telnet server_name server_port");
		printf(" [dev_name]\n");
		exit(1);
	}
	char server[INFO_BUFFER];
	char device[INFO_BUFFER];
	strcpy(server, argv[1]);
	int port = atoi(argv[2]);
	strcpy(device, argv[3]);
	
	char filterbuf[INFO_BUFFER];
	sprintf(
		filterbuf,
		"tcp port %d and host %s",
		port,
		server
	);
	
	if ((handler = open_pcap_socket_filtered(device, filterbuf))) {
		if ((netcons = open_libnet_handler(device))) {
			signal(SIGTERM, leavesniffer);
			signal(SIGINT, leavesniffer);
			signal(SIGQUIT, leavesniffer);
			main_loop(handler);
			leavesniffer(0);	
		}
	}

	
}

