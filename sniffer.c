/**
 * sniffer.c
 */

// TODO: implement according to specification.

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

pcap_t* handler;

void leavesniffer(int sig) {
	struct pcap_stat stats;
	if (pcap_stats(handler, &stats) >= 0) {
		// printf("%d pkts rcvd\n", stats.ps_recv);
		// printf("%d pkts drpd\n\n", stats.ps_drop);
	}
	pcap_close(handler);
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


void sniffer_main_loop(pcap_t* pd) {
	struct pcap_pkthdr *pktHeader;
	const u_char *pktData;
	int status;
	status = pcap_next_ex(pd, &pktHeader, &pktData);
	
	switch (status) {
		case 1:
			parse_pkt(pktHeader, pktData);		
			sniffer_main_loop(pd);
			break;
		case 0: 
			sniffer_main_loop(pd);
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

	if (argc != 2 && argc != 1) {
		printf("Usage: sniffer [dev_name]");
		exit(1);
	}
	char inputDevice[128];
	if (argc == 2) {
		strcpy(inputDevice, argv[1]);
	}

	char filterbuf[] = "not port 22";	
	if ((handler = open_pcap_socket_filtered(inputDevice, filterbuf))) {
		signal(SIGTERM, leavesniffer);
		signal(SIGINT, leavesniffer);
		signal(SIGQUIT, leavesniffer);
		sniffer_main_loop(handler);
		leavesniffer(0);		
	}

	return 0;
}
