#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <string.h>
#include <ctype.h>

#define BUFFER_SIZE 65536
#define LISTENER "wlo1"

void printMac(const unsigned char *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload(char *buffer, size_t offset, ssize_t len)
{
    if (offset >= (size_t)len || offset == 0)
    {
        return;
    }
    for (size_t i = offset; i < (size_t)len; i++)
    {
        unsigned char c = buffer[i];
        printf("%c", isprint(c) ? c : '.');
    }
    printf("\n");
}

void TCPParser(ssize_t len, char *buffer, size_t *offset)
{
    if ((size_t)len < *offset + sizeof(struct tcphdr))
    {
        return;
    }
    struct tcphdr *tcp_rec = (struct tcphdr *)(buffer + *offset);
    size_t tcp_len = tcp_rec->doff * 4;
    if (tcp_len < sizeof(struct tcphdr) || tcp_len + *offset > (size_t)len)
    {
        return;
    }
    uint16_t src_port = ntohs(tcp_rec->source);
    uint16_t dst_port = ntohs(tcp_rec->dest);
    printf("\t\t [TCP]\n\t\t\tPort: %u -> %u \n", src_port, dst_port);
    *offset += tcp_len;
    printf(" [Payload]\n");
    print_payload(buffer, *offset, len);
}

void UDPParser(ssize_t len, char *buffer, size_t *offset)
{
    if ((size_t)len < *offset + sizeof(struct udphdr))
    {
        return;
    }
    struct udphdr *udp_rec = (struct udphdr *)(buffer + *offset);
    size_t udplen = ntohs(udp_rec->uh_ulen);
    if (udplen < sizeof(struct udphdr) || udplen + *offset > (size_t)len)
    {
        return;
    }
    printf("\t\t [UDP]\n\t\t\tPort: %u -> %u \n", ntohs(udp_rec->uh_sport), ntohs(udp_rec->uh_dport));
    *offset += sizeof(struct udphdr);
    printf("\t\t[Payload]\n");
    print_payload(buffer, *offset, len);
}

void portRetriever6(char *buffer, ssize_t len, struct ip6_hdr *ip_rec, size_t *offset)
{
    uint8_t next_proto = ip_rec->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    size_t current_offset = *offset;
    while (next_proto == IPPROTO_HOPOPTS || next_proto == IPPROTO_ROUTING || next_proto == IPPROTO_DSTOPTS)
    {
        if (current_offset + sizeof(struct ip6_ext) > (size_t)len)
        {
            return;
        }
        struct ip6_ext *ip6 = (struct ip6_ext *)(buffer + current_offset);
        size_t ext_len = (ip6->ip6e_len + 1) * 8;

        next_proto = ip6->ip6e_nxt;
        current_offset += ext_len;

        if (current_offset >= (size_t)len)
        {
            return;
        }
    }
    *offset = current_offset;
    if (next_proto == IPPROTO_TCP)
    {
        TCPParser(len, buffer, offset);
    }
    else if (next_proto == IPPROTO_UDP)
    {
        UDPParser(len, buffer, offset);
    }
}

void ip4Retriever(int sock_fd, char *buffer, ssize_t len, size_t *offset)
{
    if ((size_t)len < *offset + sizeof(struct iphdr))
    {
        return;
    }
    struct iphdr *iph = (struct iphdr *)(buffer + *offset);
    size_t ip_header_len = iph->ihl * 4;
    if (ip_header_len < sizeof(struct iphdr) || (*offset + ip_header_len) > (size_t)len)
    {
        return;
    }
    *offset += ip_header_len;
    char srcIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    struct in_addr src_addr, dest_addr;

    src_addr.s_addr = iph->saddr;
    dest_addr.s_addr = iph->daddr;

    inet_ntop(AF_INET, &src_addr, srcIP, sizeof(srcIP));
    inet_ntop(AF_INET, &dest_addr, destIP, sizeof(destIP));
    printf("\t[IPV4 Header] \n");
    printf("\t\tSource IP      : %s\n", srcIP);
    printf("\t\tDestination IP : %s\n", destIP);
    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        TCPParser(len, buffer, offset);
        break;
    case IPPROTO_UDP:
        UDPParser(len, buffer, offset);
        break;
    case IPPROTO_ICMP:
        printf("(ICMP)\n");
        printf("\n");
        break;
    default:
        printf("(Other Transport Protocol)\n");
        printf("\n");
        break;
    }
}

void ip6Retriever(int sock_fd, char *buffer, ssize_t len, size_t *offset)
{
    if ((size_t)len < *offset + sizeof(struct ip6_hdr))
    {
        return;
    }
    struct ip6_hdr *ipaddr = (struct ip6_hdr *)(buffer + *offset);
    char src_addr[INET6_ADDRSTRLEN];
    char dest_addr[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &(ipaddr->ip6_src), src_addr, sizeof(src_addr));
    inet_ntop(AF_INET6, &(ipaddr->ip6_dst), dest_addr, sizeof(dest_addr));
    printf("\t[IPV6 Header] \n");
    printf("\t\tSource IP: %s\n", src_addr);
    printf("\t\tDestination IP: %s\n", dest_addr);
    portRetriever6(buffer, len, ipaddr, offset);
}

void MacRetriever(int sock_fd, char *buffer)
{
    ssize_t len = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (len < (ssize_t)sizeof(struct ethhdr))
    {
        return;
    }
    size_t offset = sizeof(struct ethhdr);
    struct ethhdr *eth = (struct ethhdr *)buffer;
    unsigned short proto = ntohs(eth->h_proto);
    printf("\n[Captured Frame] Length: %zd bytes\n", len);
    printf("  Src MAC : ");
    printMac(eth->h_source);
    printf("\n");
    printf("  Dst MAC : ");
    printMac(eth->h_dest);
    printf("\n");
    if (proto == ETH_P_IP)
    {
        ip4Retriever(sock_fd, buffer, len, &offset);
    }
    else if (proto == ETH_P_ARP)
    {
        printf(" [ARP Header] : (0x:%04X) \n", proto);
    }
    else if (proto == ETH_P_IPV6)
    {
        ip6Retriever(sock_fd, buffer, len, &offset);
    }
    else
    {
        printf(" [Other] : (0x:%04X) \n", proto);
    }
}

int main()
{
    int sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd < 0)
    {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }
    int listen_index = if_nametoindex(LISTENER);
    if (listen_index == 0)
    {
        fprintf(stderr, "Device %s not found\n", LISTENER);
        close(sock_fd);
        return EXIT_FAILURE;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = listen_index;

    if (bind(sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        perror("Socket binding failed");
        close(sock_fd);
        return EXIT_FAILURE;
    }
    struct packet_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = listen_index;

    if (setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0)
    {
        perror("setsockopt promiscious failed");
        close(sock_fd);
        return EXIT_FAILURE;
    }
    unsigned char buffer[BUFFER_SIZE];
    while (1)
    {
        MacRetriever(sock_fd, buffer);
        printf("\n");
    }
    close(sock_fd);
    return EXIT_SUCCESS;
}