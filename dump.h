#include <stdint.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <linux/in6.h>

#define INET_ADDRSTRLEN 	16
#define INET6_ADDRSTRLEN	46

typedef struct {
    __be16    ar_hrd;    /* format of hardware address */
    __be16    ar_pro;    /* format of protocol address */
    unsigned char    ar_hln;    /* length of hardware address */
    unsigned char    ar_pln;    /* length of protocol address */
    __be16    ar_op;    /* ARP opcode (command) */
    unsigned char    ar_sha[ETH_ALEN];    /* sender hardware address */
    unsigned char    ar_sip[4];    /* sender IP address */
    unsigned char    ar_tha[ETH_ALEN];    /* target hardware address */
    unsigned char    ar_tip[4];    /* target IP address */
} arphdr;

typedef struct {
    uint16_t  id;
    uint16_t  qr: 1,
              opcode: 4,
              AA: 1,
              TC: 1,
              RD: 1,
              RA: 1,
              Z: 1,
              AD: 1,
              CD: 1,
              rcode: 4;
    uint16_t  nQuestions;
    uint16_t  nAnswers;
    uint16_t  nAuthRR;
    uint16_t  nAddRR;
} dnshdr;

typedef struct ethhdr ethhdr;
typedef struct iphdr iphdr;
typedef struct ipv6hdr ipv6hdr;
typedef struct icmphdr icmphdr;
typedef struct icmp6hdr icmp6hdr;
typedef struct tcphdr tcphdr;
typedef struct udphdr udphdr;
