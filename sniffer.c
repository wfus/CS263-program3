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
		//printf("%d pkts rcvd\n", stats.ps_recv);
		//printf("%d pkts drpd\n\n", stats.ps_drop);
	}
	pcap_close(handler);
	exit(0);
}


void parse_pkt(struct pcap_pkthdr* header, const u_char* data) {
	log_everything(header, data);
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
			printf("libpcap error in mainloop() - exiting...\n");
			leavesniffer(1);
			break;
		case -2:
			printf("Breakloop called - exiting...\n");
			leavesniffer(0);
			break;
		default:
			printf("Recieved unrecognized status in mainloop()...\n");
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
		
		struct sigaction s;
		memset(&s, 0, sizeof(s));
		s.sa_handler = leavesniffer;
		
		sigaction(SIGTERM, &s, NULL);
		sigaction(SIGINT, &s, NULL);
		sigaction(SIGQUIT, &s, NULL);
			
		sniffer_main_loop(handler);
		leavesniffer(0);		
	}

	return 0;
}
