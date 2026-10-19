C Raw Socket Network Sniffer

A modular, low-level packet capture and protocol analysis tool written in C for Linux systems using raw packet sockets (AF_PACKET, SOCK_RAW).

This project explores network communication from Layer 2 up to the Application Layer payload, implemented through both focused standalone inspection scripts (which exhaustively dump structure fields) and a unified sniffer pipeline.

Architecture & Project Structure

The project is structured into two tracks:

    Standalone Deep-Dive Parsers: Dedicated scripts designed to inspect every available struct member and bitwise parameter possible in each protocol header.

    Integrated Engine (sniffing.c): A unified, high-performance packet processing pipeline that handles end-to-end decapsulation, dynamic offset navigation (including ARP and IPv6 extension headers), and payload extraction.


Script Overview & Parameter Coverage
1. printing_mac.c (Layer 2 – Ethernet Frame)

Focuses specifically on link-layer frames. Rather than printing bare MAC addresses, it unpacks all available parameters in the Ethernet header layout (struct ethhdr / struct vlan_ethhdr):

    Source and Destination MAC addresses formatted in hexadecimal byte pairs (%02X:%02X:...).

    Encapsulated EtherType / protocol ID resolution (IPv4 0x0800, IPv6 0x86DD, ARP 0x0806, 802.1Q 0x8100).

    IEEE 802.1Q VLAN Tag parameters: Tag Protocol Identifier (TPID), Priority Code Point (PCP), Drop Eligible Indicator (DEI), and 12-bit VLAN IDs.

2. printing_ip.c (Layer 3 – Network Layer)

Performs an exhaustive decode of all potential fields within the network headers (struct iphdr and struct ip6_hdr):

    IPv4:

        Version and dynamic Internet Header Length (IHL).

        Full Type of Service (ToS) dissection: Differentiated Services Code Point (DSCP, upper 6 bits) and Explicit Congestion Notification (ECN, lower 2 bits).

        Total length, 16-bit Identification, Time to Live (TTL), and Header Checksum.

        Fragmentation breakdown: Reserved bit, Don't Fragment (DF), More Fragments (MF), and Fragment Offset.

        Source and destination IPv4 addresses via inet_ntop().

    IPv6:

        Traffic Class, Flow Label, 40-byte base header layout, payload length, and Hop Limit.

        128-bit source and destination IPv6 addresses.

3. printing_port.c (Layer 4 – Transport Layer)

Isolates transport headers to analyze the operational state of Layer 4 connections (struct tcphdr and struct udphdr):

    TCP (struct tcphdr):

        Source and destination application ports (host byte order conversion via ntohs()).

        32-bit Sequence Numbers (seq) and Acknowledgment Numbers (ack_seq) converted via ntohl().

        TCP Data Offset (doff) for dynamic options boundary tracking.

        Flow control Window Size (window), Checksum, and Urgent Pointer.

        Complete control flag status breakdown: SYN, ACK, FIN, RST, PSH, URG, ECE, CWR.

    UDP (struct udphdr):

        Source and destination ports.

        Total datagram length (len) and checksum validation.

4. printing_payload.c (Application Layer / Payload Extraction)

Handles memory bounds checking and pointer math to safely expose raw data carried inside transport segments:

Dynamically resolves payload start offsets:

    UDP: 

        Offset=L4 Offset+sizeof(struct udphdr)

    TCP: 

        Offset=L4 Offset+(tcph→doff×4)

Traverses chained IPv6 extension headers (Hop-by-Hop, Routing, Destination Options) using the ((ext→ip6e_len+1)×8) boundary calculation to find the true payload root.
Iterates over payload bounds with isprint() guards to display readable ASCII characters without risking buffer over-reads.

5. sniffing.c (Integrated Sniffer)

The combined master program. It sets up the raw interface socket, enforces promiscuous reception via PACKET_MR_PROMISC, checks frame sizes against runts, and cascades parsing dynamically:
Ethernet / ARP / IPv6 ⟶ TCP / UDP /Payload

Prerequisites:

    OS: Linux kernel 2.6+ (requires AF_PACKET and SOCK_RAW).

    Compiler: GCC / Clang

    Permissions: Raw socket allocation requires either root privileges or the POSIX CAP_NET_RAW capability.

Compilation:

You can compile any of the individual scripts or the integrated engine using standard gcc flags:

    Bash
    # Compile standalone diagnostic parsers
    gcc -Wall -Wextra -O2 -o printing_mac printing_mac.c
    gcc -Wall -Wextra -O2 -o printing_ip printing_ip.c
    gcc -Wall -Wextra -O2 -o printing_port printing_port.c
    gcc -Wall -Wextra -O2 -o printing_payload printing_payload.c
    
    # Compile the fully integrated sniffer
    gcc -Wall -Wextra -O2 -o sniffing sniffing.c

Execution: 

Option 1: Grant Capabilities (Recommended, No sudo)

To execute the sniffer as a standard user without full root privileges, grant the binary CAP_NET_RAW:


    Bash
    sudo setcap cap_net_raw+ep ./sniffing
    ./sniffing

To remove the capability later:


    Bash
    sudo setcap -r ./sniffing

Option 2: Run with Superuser Privileges


    Bash
    sudo ./sniffing

Configuration: 

Before running, verify your active network interface name:


    Bash
    ip link show

Ensure the #define LISTENER macro in the script matches your active network device (e.g., eth0, eno1, or wlo1):


    C
    #define LISTENER "wlo1"

Disclaimer

This software is developed strictly for educational purposes, security analysis, and network protocol diagnostics. Sniffing packets on networks where you do not possess explicit administrative authorization may violate local laws and organizational acceptable use policies.
