#include <pcap.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>

pcap_t* open_pcap_socket(char* netdevice);
