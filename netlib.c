#include "netlib.h"
#include "sniffer.h"

#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#include <string.h>
#include <pcap.h>
#include <stdbool.h>


pcap_t* open_pcap_socket(char* netdevice) {
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_t* pd; 
	struct bpf_program fp;             /* compiled filter */
	char filter_exp[] = "not port 22"; /* actual filter */	
	
	
	pd = pcap_open_live(netdevice, MAX_IP_PKT_SIZE, 1, 0, ebuf);
	if (pd == NULL) {
		printf("Error opening pcap socket: %s\n", ebuf);
		return NULL;
	}
	if (pcap_compile(pd, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) != 0) {
		printf("Couldn't compile filter %s: %s\n",
			filter_exp,
			pcap_geterr(pd)
		);
		return NULL;
	}
	if (pcap_setfilter(pd, &fp) != 0) {
		printf("Couldn't apply filter %s, %s\n",
			filter_exp,
			pcap_geterr(pd)
		);
		return NULL;
	}
	return pd; 
}

