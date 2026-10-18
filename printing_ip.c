#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <string.h>

#define BUFFER_SIZE 65536
#define LISTENER "wlo1"

void ip4Retriever(int sock_fd, char *buffer, ssize_t len)
{
    if ((size_t)len < sizeof(struct ethhdr) + sizeof(struct iphdr))
    {
        return;
    }
    struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ethhdr));
    size_t ip_header_len = iph->ihl * 4;

    if (ip_header_len < sizeof(struct iphdr) || (sizeof(struct ethhdr) + ip_header_len) > (size_t)len)
    {
        return;
    }

    char srcIP[INET_ADDRSTRLEN];
    char destIP[INET_ADDRSTRLEN];
    struct in_addr src_addr, dest_addr;

    src_addr.s_addr = iph->saddr;
    dest_addr.s_addr = iph->daddr;

    inet_ntop(AF_INET, &src_addr, srcIP, sizeof(srcIP));
    inet_ntop(AF_INET, &dest_addr, destIP, sizeof(destIP));

    printf("\n[IPv4 Header] Total Len: %u bytes | Header Len: %zu bytes\n", ntohs(iph->tot_len), ip_header_len);
    printf("    Source IP      : %s\n", srcIP);
    printf("    Destination IP : %s\n", destIP);
    printf("    TTL            : %u\n", iph->ttl);
    printf("    DSCP: %u\n", iph->tos>>2);
    printf("    Protocol       : %u ", iph->protocol);
    switch (iph->protocol)
    {
    case IPPROTO_TCP:
        printf("(TCP)\n");
        break;
    case IPPROTO_UDP:
        printf("(UDP)\n");
        break;
    case IPPROTO_ICMP:
        printf("(ICMP)\n");
        break;
    default:
        printf("(Other Transport Protocol)\n");
        break;
    }
}

void ip6Retriever(int sock_fd, char *buffer, ssize_t len)
{
    if ((size_t)len < sizeof(struct ethhdr) + sizeof(struct ip6_hdr))
    {
        return;
    }
    struct ip6_hdr *ipaddr = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
    char src_addr[INET6_ADDRSTRLEN];
    char dest_addr[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &(ipaddr->ip6_src), src_addr, sizeof(src_addr));
    inet_ntop(AF_INET6, &(ipaddr->ip6_dst), dest_addr, sizeof(dest_addr));
    printf("\n [IPV6 Header] \n");
    printf("    Source IP: %s\n", src_addr);
    printf("    Destination IP: %s\n", dest_addr);
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
        struct ethhdr *eth = (struct ethhdr *)buffer;
        if (ntohs(eth->h_proto) == ETH_P_IP)
        {
            ip4Retriever(sock_fd, buffer, len);
        }
        else if (ntohs(eth->h_proto) == ETH_P_IPV6)
        {
            ip6Retriever(sock_fd, buffer, len);
        }
    }
    close(sock_fd);
    return EXIT_SUCCESS;
}