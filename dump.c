#include "dump.h"
#include "lex.yy.c"
#include "parser.c"
#include "filter.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/ioctl.h>


//TODO: Enable promiscuous sniffing


void usage(char *argv[])
{
    fprintf(stderr, "Usage: %s [-i interface] [-h] [filter expr]\n", argv[0]);
    exit(1);
}


void hexdump(uint8_t *data, uint32_t len)
{
    uint32_t i, j;

    for (i = 0; i < len; i += 16) {
        printf("%08x  ", i);

        // Print hex representation
        for (j = 0; j < 8; ++j) {
            if (i + j >= len) {
                printf("   ");
            }
            else {
                printf("%02hhx ", data[i + j]);
            }
        }
        for (j = 8; j < 16; ++j) {
            if (i + j >= len) {
                printf("   ");
            }
            else {
                printf(" %02hhx", data[i + j]);
            }
        }

        // Print ascii representation
        printf("  |");
        for (j = 0; j < 16; ++j) {
            if (i + j >= len) {
                break;
            }

            if (data[i + j] < 0x20 || data[i + j] > 0x7e) {
                printf(".");
            }
            else {
                printf("%c", data[i + j]);
            }
        }
        printf("|\n");
    }
}


int dns(uint8_t *packet, char **output)
{
    dnshdr *pdns = (dnshdr *)packet;

    if (!pdns->qr) {    // Query
    }
    
    return 0;       
}


int udp(uint8_t *packet, char **output)
{
    udphdr *pudp = (udphdr *)packet;
    uint16_t servPort;
    int layers = 0;

    if (ntohs(pudp->source) >= 32768 && ntohs(pudp->source) <= 61000) {
        servPort = ntohs(pudp->dest);
    }
    else {
        servPort = ntohs(pudp->source);
    }

    switch(servPort) {
    case 53:
        asprintf(output + 1, "DNS");
        break;
    case 123:
        asprintf(output + 1, "NTP");
        break;
    default:
        asprintf(output + 1, "Protocol not supported: %d", servPort);
    }

    asprintf(output, "%hu > %hu", ntohs(pudp->source), ntohs(pudp->dest));
    return 2;
}


int tcp(uint8_t *packet, char **output)
{
    tcphdr *ptcp = (tcphdr *)packet;
    uint16_t servPort;
    char flags[32];
    int layers = 0;

    if (ntohs(ptcp->source) >= 32768 && ntohs(ptcp->source) <= 61000) {
        servPort = ntohs(ptcp->dest);
    }
    else {
        servPort = ntohs(ptcp->source);
    }

    switch(servPort) {
    case 21:
        asprintf(output + 1, "FTP");
        break;
    case 22:
        asprintf(output + 1, "SSH");
        break;
    case 23:
        asprintf(output + 1, "TELNET");
        break;
    case 25:
        asprintf(output + 1, "SMTP");
        break;
    case 53:
        asprintf(output + 1, "DNS Transfer");
        break;
    case 80:
        asprintf(output + 1, "HTTP");
        break;
    case 443:
        asprintf(output + 1, "HTTPS");
        break;
    case 993:
        asprintf(output + 1, "IMAPS");
        break;
    case 2242:
        return -1;  // Don't show my ssh traffic since I'm on a vps
    case 3306:
        asprintf(output + 1, "MYSQL");
        break;
    case 3389:
        asprintf(output + 1, "RDP");
        break;
    case 6667:
        asprintf(output + 1, "IRC");
        break;
    case 6697:
        asprintf(output + 1, "SIRC");
        break;
    default:
        asprintf(output + 1, "Protocol not supported: %d", servPort);
    }

    asprintf(output, "%hu > %hu flags [%s%s%s%s%s%s%s%s] seq %u ack %u win %u",
            ntohs(ptcp->source), ntohs(ptcp->dest),
            ptcp->syn ? "S" : "",
            ptcp->ack ? "A" : "",
            ptcp->fin ? "F" : "",
            ptcp->rst ? "R" : "",
            ptcp->psh ? "P" : "",
            ptcp->urg ? "U" : "",
            ptcp->ece ? "E" : "",
            ptcp->cwr ? "C" : "",
            ptcp->seq, ptcp->ack_seq, ptcp->window);
    return 2;
}


int icmp6(uint8_t *packet, char **output)
{
    icmp6hdr *picmp6 = (icmp6hdr *)packet;

    asprintf(output, "ICMPv6");
    return 1;
}


int icmp(uint8_t *packet, char **output)
{
    icmphdr *picmp = (icmphdr *)packet;

    switch (picmp->type) {
    case ICMP_ECHOREPLY:
        asprintf(output, "ICMP  Echo Reply");
        break;
    case ICMP_DEST_UNREACH:
        switch (picmp->code) {
        case ICMP_NET_UNREACH:
            asprintf(output, "ICMP  Network Unreachable");
            break;
        case ICMP_HOST_UNREACH:
            asprintf(output, "ICMP  Host Unreachable");
            break;
        case ICMP_PROT_UNREACH:
            asprintf(output, "ICMP  Protocol Unreachable");
            break;
        case ICMP_PORT_UNREACH:
            asprintf(output, "ICMP  Port Unreachable");
            break;
        default:
            asprintf(output, "ICMP  Destination Unreachable Code: 0x%02x", picmp->code);
        }
    case ICMP_ECHO:
        asprintf(output, "ICMP  Echo Request");
        break;
    case ICMP_TIMESTAMP:
        asprintf(output, "ICMP  Timestamp Request");
        break;
    case ICMP_TIMESTAMPREPLY:
        asprintf(output, "ICMP  Timestamp Reply");
        break;
    default:
        asprintf(output, "ICMP  Unsupported type: 0x%02x", picmp->type);
    }

    return 1;
}


int ipv6(uint8_t *packet, char **output)
{
    ipv6hdr *pipv6 = (ipv6hdr *)packet;
    char ipsrc[INET6_ADDRSTRLEN], ipdst[INET6_ADDRSTRLEN];
    int layers = 0;

    inet_ntop(AF_INET6, &pipv6->saddr, ipsrc, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &pipv6->daddr, ipdst, INET6_ADDRSTRLEN);

    switch (pipv6->nexthdr) {
    case IPPROTO_ICMP:
        layers = icmp(packet + sizeof(ipv6hdr), output + 1);
        break;
    case IPPROTO_ICMPV6:
        layers = icmp6(packet + sizeof(ipv6hdr), output + 1);
        break;
    case IPPROTO_TCP:
        layers = tcp(packet + sizeof(ipv6hdr), output + 1);
        break;
    case IPPROTO_UDP:
        layers = udp(packet + sizeof(ipv6hdr), output + 1);
        break;
    default:
        asprintf(output + 1, "Transport layer protocol not supported: 0x%02hx", pipv6->nexthdr);
        layers = 1;
    }

    if (layers == -1) {
        return -1;
    }

    asprintf(output, "%s > %s", ipsrc, ipdst);
    return layers + 1;
}


int ip(uint8_t *packet, char **output)
{
    iphdr *pip = (iphdr *)packet;
    char ipsrc[INET_ADDRSTRLEN], ipdst[INET_ADDRSTRLEN];
    int layers = 0;

    inet_ntop(AF_INET, &pip->saddr, ipsrc, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &pip->daddr, ipdst, INET_ADDRSTRLEN);

    switch(pip->protocol) {
    case IPPROTO_ICMP:
        layers = icmp(packet + sizeof(iphdr), output + 1);
        break;
    case IPPROTO_TCP:
        layers = tcp(packet + sizeof(iphdr), output + 1);
        /*
        if (layers == -1) {
            return -1;
        }
        asprintf(output, "%s:%hu > %s:%hu",
                    ipsrc, ((tcphdr *)(packet + sizeof(iphdr)))->source,
                    ipdst, ((tcphdr *)(packet + sizeof(iphdr)))->dest);
        return layers + 1;
        */
        break;
    case IPPROTO_UDP:
        layers = udp(packet + sizeof(iphdr), output + 1);
        /*
        if (layers == -1) {
            return -1;
        }
        asprintf(output, "%s:%hu > %s:%hu",
                    ipsrc, ((udphdr *)(packet + sizeof(iphdr)))->source,
                    ipdst, ((udphdr *)(packet + sizeof(iphdr)))->dest);
        return layers + 1;
        */
        break;
    default:
        asprintf(output + 1, "Transport layer protocol not supported: 0x%02hx", pip->protocol);
        layers = 1;
    }

    if (layers == -1) {
        return -1;
    }

    asprintf(output, "%s > %s", ipsrc, ipdst);
    return layers + 1;
}


int arp(uint8_t *packet, char **output)
{
    arphdr *parp = (arphdr *)packet;
    char saddr[INET_ADDRSTRLEN], taddr[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, parp->ar_sip, saddr, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, parp->ar_tip, taddr, INET_ADDRSTRLEN);

    switch(ntohs(parp->ar_op)) {
    case ARPOP_REQUEST:
        asprintf(output, "ARP REQUEST  Who has %s? Tell %s", taddr, saddr);
        break;
    case ARPOP_REPLY:
        asprintf(output, "ARP REPLY  %s is at %02x:%02x:%02x:%02x:%02x:%02x",
                    saddr, parp->ar_sha[0], parp->ar_sha[1], parp->ar_sha[2],
                           parp->ar_sha[3], parp->ar_sha[4], parp->ar_sha[5]);
        break;
    default:
        asprintf(output, "ARP operation not supported: 0x%04hx", parp->ar_op);
    }

    return 1;
}


int eth(uint8_t *frame, char **output)
{
    ethhdr *peth = (ethhdr *)frame;
    int layers;

    switch(ntohs(peth->h_proto)) {
    case ETH_P_ARP:
        layers = arp(frame + sizeof(ethhdr), output + 1);
        break;
    case ETH_P_IP:
        layers = ip(frame + sizeof(ethhdr), output + 1);
        break;
    case ETH_P_IPV6:
        layers = ipv6(frame + sizeof(ethhdr), output + 1);
        break;
    case ETH_P_8021Q:
        asprintf(output + 1, "Vlan parsing not supported");
        layers = 1;
    default:
        asprintf(output + 1, "Frame type not supported: %04hx", ntohs(peth->h_proto));
        layers = 1;
    }

    if (layers == -1) {
        return -1;
    }

    // Parse the IP header
    asprintf(output, "%02x:%02x:%02x:%02x:%02x:%02x > %02x:%02x:%02x:%02x:%02x:%02x",
                        peth->h_source[0], peth->h_source[1], peth->h_source[2],
                        peth->h_source[3], peth->h_source[4], peth->h_source[5],
                        peth->h_dest[0], peth->h_dest[1], peth->h_dest[2],
                        peth->h_dest[3], peth->h_dest[4], peth->h_dest[5]);

    return layers + 1;
}


int getRecvTime(int sockfd, struct timeval *tv)
{
    if (ioctl(sockfd, SIOCGSTAMP, tv) < 0) {
        return -1;
    }
    return 0;
}


int dump(int sockfd, int mtu, node_t *filterExpr)
{
    uint8_t packet[sizeof(ethhdr) + mtu + ETH_FCS_LEN];     // Will result in a 65535 byte buffer on loopback interface. :/
    struct timeval recvTime;
    int numBytes, numLayers, i;
    
    char *output[8], strTime[32];
    memset(output, 0, sizeof(char *) * 4);

    while (1) {
        fflush(stdout);
        fflush(stderr);

        numBytes = recv(sockfd, packet, sizeof(packet), 0);
        getRecvTime(sockfd, &recvTime);
        strftime(strTime, 32, "%H:%M:%S", localtime(&recvTime.tv_sec));

        if (filter(filterExpr, packet, NULL) == 0) {
            continue;
        }

        numLayers = eth(packet, output);

        if (numLayers > 0) {
            printf("%s.%.6lu", strTime, recvTime.tv_usec);

            for (i = 0; i < numLayers; i++) {
                // Iterate through output
                if (output[i] == NULL) {
                    printf("  ERROR:NULL ");
                    continue;
                }
                printf("  %s\n", output[i]);
                free(output[i]);
                output[i] = NULL;
            }
            printf("\n");
        }
    }

    return 0;
}


int createSocket(int ifaceIndex)
{
    const int iphdrincl = 1;
    int sockfd;
    struct sockaddr_ll servAddr;

    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket");
        return -1;
    }

    memset(&servAddr, 0, sizeof(struct sockaddr_ll));
    servAddr.sll_family = AF_PACKET;
    servAddr.sll_protocol = htons(ETH_P_ALL);
    servAddr.sll_ifindex = ifaceIndex;

    if (bind(sockfd, (struct sockaddr *)&servAddr, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
        return -1;
    }

    return sockfd;
}


int getIfaceMtu(char *name)
{
    int fd;
    struct ifreq ifr;
    size_t nameLen = strlen(name);
    
    if (nameLen < sizeof(ifr.ifr_name )) {
        memcpy(ifr.ifr_name, name, nameLen);
        ifr.ifr_name[nameLen] = 0;
    }
    else {
        return -1;
    }

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        return -1;
    }

    if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
        return -1;
    }

    return ifr.ifr_mtu;
}


int getIfaceIndex(char *name)
{
    int fd;
    struct ifreq ifr;
    size_t nameLen = strlen(name);
    
    if (nameLen < sizeof(ifr.ifr_name )) {
        memcpy(ifr.ifr_name, name, nameLen);
        ifr.ifr_name[nameLen] = 0;
    }
    else {
        return -1;
    }

    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        return -1;
    }

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        return -1;
    }

    return ifr.ifr_ifindex;
}


int main(int argc, char *argv[])
{
    char *iface = "eth0";
    int opt, iIndex = 0, iMtu = 0, i;
    FILE *fp;
    node_t *ast;

    int sockfd;

    while ((opt = getopt(argc, argv, "i:h")) != -1) {
        switch(opt) {
        case 'i':
            iface = optarg;
            break;
        case 'h':
        default:
            usage(argv);
        }
    }

    if ((iIndex = getIfaceIndex(iface)) < 0) {
        fprintf(stderr, "Could not find interface %s\n", iface);
        usage(argv);
    }

    if ((sockfd = createSocket(iIndex)) < 0) {
        return -1;
    }

    if ((iMtu = getIfaceMtu(iface)) < 0) {
        fprintf(stderr, "Could not get MTU for interface %s\n", iface);
        usage(argv);
    }

    if (optind < argc) {
        fp = fopen(".dumpfilter", "w");
        for (i = optind; i < argc; i++) {
            fwrite(argv[i], 1, strlen(argv[i]), fp);
            fwrite(" ", 1, 1, fp);
        }
        fclose(fp);
        yyin = fopen(".dumpfilter", "r");
        ast = parse();
        typeCheck(ast);
        fclose(yyin);
        unlink(".dumpfilter");
    }
        
    printf("listening on %s, capture size %u bytes\n", iface, iMtu);
    dump(sockfd, iMtu, ast);

    close(sockfd);
    return 0;
}
