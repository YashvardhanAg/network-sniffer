#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <string.h>

#define BUFFER_SIZE 65536
#define LISTENER "wlo1"

void printMac(const unsigned char *mac)
{
    printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void MacRetriver(int sock_fd, char *buffer)
{
    ssize_t len = recvfrom(sock_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
    if (len < (ssize_t)sizeof(struct ethhdr))
    {
        return;
    }
    struct ethhdr *eth = (struct ethhdr *)buffer;
    unsigned short proto = ntohs(eth->h_proto);
    printf("\n[Captured Frame] Length: %zd bytes\n", len);
    printf("  Src MAC : ");
    printMac(eth->h_source);
    printf("\n");
    printf("  Dst MAC : ");
    printMac(eth->h_dest);
    printf("\n");
    printf("  Type    : 0x%04X ", proto);
    if (proto == ETH_P_IP)
    {
        printf("(IPv4) : (0x:%04X) \n", proto);
    }
    else if (proto == ETH_P_ARP)
    {
        printf("(ARP) : (0x:%04X) \n", proto);
    }
    else if (proto == ETH_P_IPV6)
    {
        printf("(IPv6) : (0x:%04X) \n", proto);
    }
    else
    {
        printf("(Other)  : (0x:%04X) \n", proto);
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
        MacRetriver(sock_fd, buffer);
    }
    close(sock_fd);
    return EXIT_SUCCESS;
}