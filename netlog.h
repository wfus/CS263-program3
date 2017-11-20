/* 
 * netlog.h
 * 
 * Contains code for logging information about different
 * network headers (ETHERNET, IP, TCP, ICMP)
 *
 */

#ifndef _netlog_h
#define _netlog_h

#include "sniffer.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <stdbool.h>

void log_ethernet(struct ethernet_hdr* ethheader);
void log_ip(struct ip_hdr* ipheader);
void log_tcp(struct tcp_hdr* tcpheader, int payload_size);
void log_tcp_nolength(struct tcp_hdr* tcpheader);
void log_payload(u_char* data, int length);
void log_icmp(struct icmp_hdr* icmpheader);
void log_everything(struct pcap_pkthdr* header, const u_char* data);

#endif
