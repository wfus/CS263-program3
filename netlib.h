#include <pcap.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <libnet.h>

pcap_t* open_pcap_socket(char* netdevice);
pcap_t* open_pcap_socket_filtered(char* dev, char* filter);

libnet_t* open_libnet_handler(char* device);



