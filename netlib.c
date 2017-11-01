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
	t = libnet_init(LIBNET_LINK, device, errbuf);	
	if (t == NULL) {
		printf("libnet_init() failed: %s\n", errbuf);
		return NULL;
	}
	return t;
}


