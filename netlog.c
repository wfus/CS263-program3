#include "netlog.h"
#include "sniffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void log_ethernet(struct ethernet_hdr* ethheader) {
	printf("ETHERNET: src[%02x:%02x:%02x:%02x:%02x:%02x] dst[%02x:%02x:%02x:%02x:%02x:%02x]\n", 
        ethheader->ether_src_addr[0],
		ethheader->ether_src_addr[1],
		ethheader->ether_src_addr[2],
		ethheader->ether_src_addr[3],
		ethheader->ether_src_addr[4],
		ethheader->ether_src_addr[5],
        ethheader->ether_dst_addr[0],
		ethheader->ether_dst_addr[1],
		ethheader->ether_dst_addr[2],
		ethheader->ether_dst_addr[3],
		ethheader->ether_dst_addr[4],
		ethheader->ether_dst_addr[5]
	);  
}


void log_ip(struct ip_hdr* ipheader) {
	char protocol[32];
	switch (ipheader->ip_protocol) {
		case IP_ICMP:
			strcpy(protocol, "IP_ICMP");
			break;
		case IP_TCP:
			strcpy(protocol, "IP_TCP");
			break;
		case IP_UDP:
			strcpy(protocol, "IP_UDP");
			break;
		default:
			strcpy(protocol, "PROTOCOL_UNKNOWN");
			break;  
	}   
	printf("IP: src[%s] dst[%s]\n", 
		inet_ntoa(ipheader->ip_src_addr),   
		inet_ntoa(ipheader->ip_dst_addr)
	);  
	printf("\tip_hdr_len[%d] ip_data_len[%d] Protocol: %s\n",
		(ipheader->ip_hlen * 4),
		(ntohs(ipheader->ip_len) - (ipheader->ip_hlen * 4)),
		protocol
	);
}


void log_tcp(struct tcp_hdr* tcpheader, int payload_size) {
	char flag[128];
	char* curr = flag;
	if (tcpheader->tcp_flags & TCP_FIN) curr += sprintf(curr, " %s", "FIN");
	if (tcpheader->tcp_flags & TCP_SYN) curr += sprintf(curr, " %s", "SYN");
	if (tcpheader->tcp_flags & TCP_RST) curr += sprintf(curr, " %s", "RST");
	if (tcpheader->tcp_flags & TCP_PUSH) curr += sprintf(curr, " %s", "PUSH");
	if (tcpheader->tcp_flags & TCP_ACK) curr += sprintf(curr, " %s", "ACK");
	if (tcpheader->tcp_flags & TCP_URG) curr += sprintf(curr, " %s", "URG");
	if (tcpheader->tcp_flags & TCP_ECE) curr += sprintf(curr, " %s", "ECE");
	if (tcpheader->tcp_flags & TCP_CWR) curr += sprintf(curr, " %s", "CWR");


	printf("TCP: ");
    printf("src_port[%d] dst_port[%d]\n",
        ntohs(tcpheader->tcp_src_port),
        ntohs(tcpheader->tcp_dst_port)
    );
	printf("\tseq_num[%u] ack_num[%u]\n",
		ntohl(tcpheader->tcp_seq),
		ntohl(tcpheader->tcp_ack)	
	);
	int tcp_header_len = (tcpheader->tcp_off) * 4;
    printf("\ttcp_hdr_len[%d] tcp_data_len[%d] flags: %s\n",
		tcp_header_len,
		payload_size,
		flag
	);
}


void log_tcp_nolength(struct tcp_hdr* tcpheader) {
	char flag[128];
	char* curr = flag;
	if (tcpheader->tcp_flags & TCP_FIN) curr += sprintf(curr, " %s", "FIN");
	if (tcpheader->tcp_flags & TCP_SYN) curr += sprintf(curr, " %s", "SYN");
	if (tcpheader->tcp_flags & TCP_RST) curr += sprintf(curr, " %s", "RST");
	if (tcpheader->tcp_flags & TCP_PUSH) curr += sprintf(curr, " %s", "PUSH");
	if (tcpheader->tcp_flags & TCP_ACK) curr += sprintf(curr, " %s", "ACK");
	if (tcpheader->tcp_flags & TCP_URG) curr += sprintf(curr, " %s", "URG");
	if (tcpheader->tcp_flags & TCP_ECE) curr += sprintf(curr, " %s", "ECE");
	if (tcpheader->tcp_flags & TCP_CWR) curr += sprintf(curr, " %s", "CWR");


	printf("TCP: ");
    printf("src_port[%d] dst_port[%d]\n",
        ntohs(tcpheader->tcp_src_port),
        ntohs(tcpheader->tcp_dst_port)
    );
	printf("\tseq_num[%d] ack_num[%d]\n",
		ntohl(tcpheader->tcp_seq),
		ntohl(tcpheader->tcp_ack)	
	);
    printf("\ttcp_hdr_len[] tcp_data_len[] flags:%s\n",
		flag
	);
}

void print_ascii_line(const u_char* payload, int length, int offset) {
	const u_char* ch;
	ch = payload;
	for (int i = 0; i < length; i++) {
		if (isprint(*ch)) printf("%c", *ch);
		else              printf(""); // non-ascii character
		ch++;	
	}
	printf("\n");
	return;
}


void print_hex_ascii_line(const u_char* payload, int length, int offset) {
	int gap;
	const u_char *ch;

	// offset
	printf("%05d    ", offset);
	
	// hex
	ch = payload;
	for (int i = 0; i < length; i++) {
		printf("%02x ", *ch);
		ch++;
		// print extra space after every 8th byte
		if (i % 8 == 7) printf(" ");	
	}

	/* print space to handle line less than 8 bytes */
	if (length < 8) printf(" ");

	/* fill hex gap with spaces if not full line */
	if (length < 16) {
		gap = 16 - length;
		for (int i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("    ");

	/* print out ASCII if printable */
	ch = payload;
	for (int i = 0; i < length; i++) {
		if (isprint(*ch)) printf("%c", *ch);
		else              printf(".");
		ch++;
	}

	printf("\n");
	return;
}


void log_payload(u_char* payload, int length) {

	int remaining = length;
	int line_width = 16;
	int line_len;
	int offset = 0;
	const u_char *ch = payload;
	int printed_ctr = 0;

	/*
	while(length > 0) {
		if (isprint(*ch)) {
			printf("%c", *ch);
			printed_ctr++;
		}
		if (printed_ctr % 16 == 0) printf("\n");
		ch++;
		length--;
	}
	*/
	
	if (length <= 0) return;
	if (length <= line_width) {
		print_ascii_line(ch, length, offset);
		return;
	}

	for (;;) {
		line_len = line_width % remaining;
		print_ascii_line(ch, line_len, offset);
		remaining -= line_len;
		ch += line_len;
		offset = offset + line_width;
		if (remaining <= line_width) {
			print_ascii_line(ch, remaining, offset);
			break;
		}
	}
	return;
}


void log_icmp(struct icmp_hdr* icmpheader) {
	printf("ICMP: ");
	char type[64];
	switch (icmpheader->type) {
		case ICMP_ECHOREPLY:
			strcpy(type, "ICMP_ECHOREPLY");
			break;
		case ICMP_DEST_UNREACH:
			strcpy(type, "ICMP_DEST_UNREACH");
			break;
		case ICMP_SOURCE_QUENCH:
            strcpy(type, "ICMP_SOURCE_QUENCH");
            break;
		case ICMP_REDIRECT:
            strcpy(type, "ICMP_REDIRECT");
            break;
		case ICMP_ECHO:
            strcpy(type, "ICMP_ECHO");
            break;
		case ICMP_TIME_EXCEEDED:
            strcpy(type, "ICMP_TIME_EXCEEDED");
            break;
		case ICMP_PARAMETERPROB:
            strcpy(type, "ICMP_PARAMETERPROB");
            break;
		case ICMP_TIMESTAMP:
            strcpy(type, "ICMP_TIMESTAMP");
            break;
		case ICMP_TIMESTAMPREPLY:
	        strcpy(type, "ICMP_TIMESTAMPREPLY");
	        break;
		case ICMP_INFO_REQUEST:
	        strcpy(type, "ICMP_INFO_REQUEST");
	        break;
		case ICMP_INFO_REPLY:
	        strcpy(type, "ICMP_INFO_REPLY");
	        break;
		case ICMP_ADDRESS:
	        strcpy(type, "ICMP_ADDRESS");
	        break;
		case ICMP_ADDRESSREPLY:
	        strcpy(type, "ICMP_ADDRESSREPLY");
	        break;
		default:
	        strcpy(type, "ICMP_OTHER");
			break;
	}
	printf("type[%s] id[%hu] seq[%hu]\n",
		type,
		ntohs(icmpheader->un.echo.id),
		ntohs(icmpheader->un.echo.seq)
	);

}




