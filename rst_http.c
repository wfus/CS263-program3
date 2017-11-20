/**
 * rst_http.c
 */

#include "sniffer.h"
#include "netlib.h"
#include "netlog.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <pcap.h>
#include <stdbool.h>
#include <libnet.h>
#include <unistd.h>

#define DEVICE_BUF_SIZE 128


pcap_t* handler;
libnet_t* netcons;

int counter;

struct ethernet_hdr* global_ethheader;
struct ip_hdr* global_ipheader;
struct tcp_hdr* global_tcpheader;
uint32_t global_seq;


void leave(int sig) {
	pcap_close(handler);
	libnet_destroy(netcons);
	exit(0);
}


void parse_pkt(struct pcap_pkthdr* header, const u_char* data) {
	log_everything(header, data);
	attack_packet(netcons, header, data);
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
		case -2:
			printf("Breakloop called - exiting...");
			leave(0);
		default:
			printf("Recieved unrecognized status in mainloop().");
			leave(1);
	}
	return;
}


int main (int argc, char** argv) {
	if (argc < 2 || argc > 3) {
		printf("Usage: ./rst_http.c <port> [dev_name]\n");
		exit(1);
	}
	int port = atoi(argv[1]);
	char device[DEVICE_BUF_SIZE];
	if (argc == 3) {
		strncpy(device, argv[2], DEVICE_BUF_SIZE);
	}

	struct sigaction s;
	memset(&s, 0, sizeof(s));
	s.sa_handler = leave;
	sigaction(SIGTERM, &s, NULL);
   	sigaction(SIGINT, &s, NULL);
	sigaction(SIGQUIT, &s, NULL);	
		
	char filterbuf[DEVICE_BUF_SIZE];
	sprintf(filterbuf, "tcp port %d and src port %d and inbound", port, port);
	if ((handler = open_pcap_socket_filtered(device, filterbuf))) {
		if ((netcons = open_libnet_handler(device))) {
			main_loop(handler);
			leave(0);
		}
	}
	return 0;	
}
