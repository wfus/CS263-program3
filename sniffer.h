/**
 * sniffer.h
 *
 * Defines useful structs for Ethernet, IP, and TCP
 * headers. Inspired by code found in the official
 * libpcap tutorial:
 *     http://www.tcpdump.org/pcap.html
 */

#ifndef __SNIFFER_H__
#define __SNIFFER_H__

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <endian.h>

//Ethernet addresses are 6 bytes long.
#define ETH_ADDR_LEN	6

//The maximum size of an Ethernet frame, including
//the header.
#define MAX_ETH_FRAME_LEN   1522

//The size of a word in the machines we will be using
#define INFO_WORD_SIZE 4


//Ethernet header
struct ethernet_hdr{
        u_char  ether_dst_addr[ETH_ADDR_LEN]; /* destination host address */
        u_char  ether_src_addr[ETH_ADDR_LEN]; /* source host address */
        u_short ether_type;                   /* IP? ARP? RARP? etc */
};
#define ETHER_HDR_LEN	14				/* compilers often pad structs to be 4-byte
										 * aligned, such that sizeof(ethernet_hdr)
										 * would be 16. However, when we read raw
										 * packets using libcap, the Ethernet header
										 * will not be padded!
										 */	

//IP header (note that an IP header will always
//be 20 bytes long, a size which is a multiple of
//4 bytes, and thus won't be padded by the compiler).
struct ip_hdr{
#if __BYTE_ORDER == __LITTLE_ENDIAN
        u_char ip_hlen:4;               /* length of the IP header */
        u_char ip_version:4;            /* IP protocol version */
#else
        u_char ip_version:4;            /* IP protocol version */
        u_char ip_hlen:4;               /* length of the IP header */
#endif
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_protocol;            /* protocol */
		#define IP_ICMP 1               /* some popular protocol types . . .*/
		#define IP_TCP  6
		#define IP_UDP  17
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src_addr,
                        ip_dst_addr;    /* source and dest address */
};

#define MAX_IP_PKT_SIZE     (1 << 16)


//TCP header
struct tcp_hdr{
        u_short tcp_src_port;            /* source port */
        u_short tcp_dst_port;            /* destination port */
        u_int32_t tcp_seq;               /* sequence number */
        u_int32_t tcp_ack;               /* acknowledgement number */
#if __BYTE_ORDER == __LITTLE_ENDIAN
        u_char tcp_unused:4;
        u_char tcp_off:4;                /* data offset */
#else
        u_char tcp_off:4;                /* data offset */
        u_char tcp_unused:4;
#endif
        u_char  tcp_flags;
        #define TCP_FIN  0x01
        #define TCP_SYN  0x02
        #define TCP_RST  0x04
        #define TCP_PUSH 0x08
        #define TCP_ACK  0x10
        #define TCP_URG  0x20
        #define TCP_ECE  0x40
        #define TCP_CWR  0x80
        #define TCP_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short tcp_win;                 /* window */
        u_short tcp_sum;                 /* checksum */
        u_short tcp_urp;                 /* urgent pointer */
};
#define MAX_TCP_HDR_OPTIONS_LEN		40	/* a TCP header can have between 0
										 * and 40 bytes of options */

struct icmp_hdr{
  u_char type;		/* message type */
  u_char code;		/* type sub-code */
  u_short checksum;
  union{
    struct{
      u_short	id;
      u_short	seq;
    } echo;			/* echo datagram */
    u_int32_t		gateway;	/* gateway address */
    struct{
      u_short	__unused;
      u_short	mtu;
    } frag;			/* path mtu discovery */
  } un;
};

#define ICMP_ECHOREPLY		0	/* Echo Reply				*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench			*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO			8	/* Echo Request				*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded			*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply			*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/


#endif  //#ifndef __SNIFFER_H__
