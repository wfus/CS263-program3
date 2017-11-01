#include "sniffer.h"
#include "netlog.h"

#include <pcap.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <libnet.h>


struct packet_info {
	unsigned int total_len;
	unsigned int tcp_header_len;
	unsigned int app_header_len;
};

pcap_t* open_pcap_socket(char* netdevice);
pcap_t* open_pcap_socket_filtered(char* dev, char* filter);

libnet_t* open_libnet_handler(char* device);


void calculate_packet_sizes(const u_char *packet, struct packet_info* info);

void attack_packet(libnet_t* l, struct pcap_pkthdr* cap_header, const u_char* packet);

void send_tcp_packet(libnet_t* l, struct in_addr srcip, struct in_addr dstip, u_short srcport, u_short dstport, uint32_t seq, uint32_t ack, struct ethernet_hdr* ethheader);

