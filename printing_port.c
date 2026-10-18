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

#define BUFFER_SIZE 65536
#define LISTENER "wlo1"

void TCPParser(ssize_t len, char *buffer, size_t offset)
{
    if ((size_t)len < offset + sizeof(struct tcphdr))
    {
        return;
    }
    struct tcphdr *tcp_rec = (struct tcphdr *)(buffer + offset);
    size_t tcp_len = tcp_rec->doff * 4;
    if (tcp_len < sizeof(struct tcphdr) || tcp_len + offset > (size_t)len)
    {
        return;
    }

    uint16_t src_port = ntohs(tcp_rec->source);
    uint16_t dst_port = ntohs(tcp_rec->dest);
    uint32_t seq_num = ntohl(tcp_rec->seq);
    uint32_t ack_num = ntohl(tcp_rec->ack_seq);
    uint16_t window = ntohs(tcp_rec->window);
    printf("    [TCP] Port: %u -> %u | Flags: [ %s%s%s%s%s%s] | Seq: %u | Ack: %u | Win: %u\n", src_port, dst_port, tcp_rec->syn ? "SYN " : "", tcp_rec->ack ? "ACK " : "", tcp_rec->fin ? "FIN " : "", tcp_rec->rst ? "RST " : "", tcp_rec->psh ? "PSH " : "", tcp_rec->urg ? "URG " : "", seq_num, ack_num, window);
}

void UDPParser(ssize_t len, char *buffer, size_t offset)
{
    if ((size_t)len < offset + sizeof(struct udphdr))
    {
        return;
    }
    struct udphdr *udp_rec = (struct udphdr *)(buffer + offset);
    size_t udplen = ntohs(udp_rec->uh_ulen);
    if (udplen < sizeof(struct udphdr) || udplen + sizeof(struct ethhdr) > (size_t)len)
    {
        return;
    }
    printf("    [UDP] Port: %u -> %u | Datagram Len: %zu bytes\n", ntohs(udp_rec->uh_sport), ntohs(udp_rec->uh_dport), udplen);
}

void portRetriever(char *buffer, ssize_t len, struct iphdr *ip_rec)
{
    size_t iplen = ip_rec->ihl * 4;
    if (iplen < sizeof(struct iphdr) || (iplen + sizeof(struct ethhdr)) > (size_t)len)
    {
        return;
    }
    if (ip_rec->protocol == IPPROTO_TCP)
    {
        TCPParser(len, buffer, iplen + sizeof(struct ethhdr));
    }
    else if (ip_rec->protocol == IPPROTO_UDP)
    {
        UDPParser(len, buffer, iplen + sizeof(struct ethhdr));
    }
}

void portRetriever6(char *buffer, ssize_t len, struct ip6_hdr *ip_rec)
{
    uint8_t next_proto = ip_rec->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    size_t current_offset = sizeof(struct ip6_hdr) + sizeof(struct ethhdr);
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
    if (next_proto == IPPROTO_TCP)
    {
        TCPParser(len, buffer, current_offset);
    }
    else if (next_proto == IPPROTO_UDP)
    {
        UDPParser(len, buffer, current_offset);
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
        ssize_t len = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if ((size_t)len < sizeof(struct ethhdr))
        {
            continue;
        }
        struct ethhdr *eth = (struct ethhdr *)buffer;
        if (ntohs(eth->h_proto) == ETH_P_IP)
        {
            if ((size_t)len < sizeof(struct ethhdr) + sizeof(struct iphdr))
            {
                continue;
            }
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));
            portRetriever(buffer, len, ip);
        }
        else if (ntohs(eth->h_proto) == ETH_P_IPV6)
        {
            if ((size_t)len < sizeof(struct ethhdr) + sizeof(struct ip6_hdr))
            {
                continue;
            }
            struct ip6_hdr *ip6 = (struct ip6_hdr *)(buffer + sizeof(struct ethhdr));
            portRetriever6(buffer, len, ip6);
        }
    }
    close(sock_fd);
    return EXIT_SUCCESS;
}