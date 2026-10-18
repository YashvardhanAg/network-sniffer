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

size_t TCPsize(ssize_t len, char *buffer, size_t offset)
{
    if ((size_t)len < offset + sizeof(struct tcphdr))
    {
        return 0;
    }
    struct tcphdr *tcp_rec = (struct tcphdr *)(buffer + offset);
    size_t tcp_len = tcp_rec->doff * 4;
    if (tcp_len < sizeof(struct tcphdr) || tcp_len + offset > (size_t)len)
    {
        return 0;
    }
    return tcp_len;
}

size_t UDPsize(ssize_t len, char *buffer, size_t offset)
{
    if ((size_t)len < offset + sizeof(struct udphdr))
    {
        return 0;
    }
    return sizeof(struct udphdr);
}

size_t sizeRetriever(char *buffer, ssize_t len, struct iphdr *ip_rec)
{
    size_t iplen = ip_rec->ihl * 4;
    if (iplen < sizeof(struct iphdr) || (iplen + sizeof(struct ethhdr)) > (size_t)len)
    {
        return 0;
    }
    size_t offset = iplen + sizeof(struct ethhdr);
    if (ip_rec->protocol == IPPROTO_TCP)
    {
        return TCPsize(len, buffer, offset) + offset;
    }
    else if (ip_rec->protocol == IPPROTO_UDP)
    {
        return UDPsize(len, buffer, offset) + offset;
    }
}

size_t sizeRetriever6(char *buffer, ssize_t len, struct ip6_hdr *ip_rec)
{
    uint8_t next_proto = ip_rec->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    size_t current_offset = sizeof(struct ip6_hdr) + sizeof(struct ethhdr);
    while (next_proto == IPPROTO_HOPOPTS || next_proto == IPPROTO_ROUTING || next_proto == IPPROTO_DSTOPTS)
    {
        if (current_offset + sizeof(struct ip6_ext) > (size_t)len)
        {
            return 0;  
        }
        struct ip6_ext *ip6 = (struct ip6_ext *)(buffer + current_offset);
        size_t ext_len = (ip6->ip6e_len + 1) * 8;

        next_proto = ip6->ip6e_nxt;
        current_offset += ext_len;

        if (current_offset >= (size_t)len)
        {
            return 0;
        }
    }
    if (next_proto == IPPROTO_TCP)
    {
        return TCPsize(len, buffer, current_offset) + current_offset;
    }
    else if (next_proto == IPPROTO_UDP)
    {
        return UDPsize(len, buffer, current_offset) + current_offset;
    }
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
        ssize_t len = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if ((size_t)len < sizeof(struct ethhdr))
        {
            continue;
        }
        size_t offset = 0;
        struct ethhdr *eth = (struct ethhdr *)buffer;
        if (ntohs(eth->h_proto) == ETH_P_IP)
        {
            if ((size_t)len < sizeof(struct ethhdr) + sizeof(struct iphdr))
            {
                continue;
            }
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            offset = sizeRetriever(buffer, len, ip);
        }
        else if (ntohs(eth->h_proto) == ETH_P_IPV6)
        {
            if ((size_t)len < sizeof(struct ethhdr) + sizeof(struct ip6_hdr))
            {
                continue;
            }
            struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
            offset = sizeRetriever6(buffer, len, ip6);
        }
        else
        {
            continue;
        }
        print_payload(buffer, offset, len);
        printf("\n");
    }
    close(sock_fd);
    return EXIT_SUCCESS;
}