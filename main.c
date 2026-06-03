#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>


#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define BLUE    "\033[34m"
#define RESET   "\033[0m"


struct ipv4_header {
    uint8_t version_and_ihl;
    uint8_t dscp_and_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragmentOffset;
    uint8_t timeToLive;
    uint8_t protocol;
    uint16_t headerCheckSum;
    uint32_t sourceAddress;
    uint32_t destinationAddress;
} __attribute__((packed));

struct ipv6_header {
    uint32_t version_tclass_flow;
    uint16_t payloadLength;
    uint8_t nextHeader;
    uint8_t hop_limit;
    uint8_t sourceAddress[16];
    uint8_t destinationAddress[16];
}__attribute__((packed));

struct tcp_header {
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint32_t sequenceNumber;
    uint32_t acknowledgementNumber;
    uint8_t dataOffset_and_reserved;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} __attribute__((packed));

struct udp_header {
    uint16_t sourcePort;
    uint16_t destinationPort;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));




int main(void) {

    int packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (packet_socket == -1) {
        printf("Could not open socket\n");
        return -1;
    }

    uint8_t buffer[65536];

    while (1) {
        memset(buffer, 0, sizeof(buffer));
        int received_bytes = recvfrom(packet_socket, buffer, sizeof(buffer), 0, NULL, NULL);
        if (received_bytes < 0) {
            printf("Could not read from socket\n");
        }
        else {
            //ethernet layer
           struct ether_header *eh = (struct ether_header *)buffer;
            uint16_t ether_type = ntohs(eh->ether_type);

            char dest_mac[18];
            char src_mac[18];

            snprintf(dest_mac, sizeof(dest_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     eh->ether_dhost[0], eh->ether_dhost[1], eh->ether_dhost[2],
                     eh->ether_dhost[3], eh->ether_dhost[4], eh->ether_dhost[5]);

            snprintf(src_mac, sizeof(src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                     eh->ether_shost[0], eh->ether_shost[1], eh->ether_shost[2],
                     eh->ether_shost[3], eh->ether_shost[4], eh->ether_shost[5]);

            uint16_t e_protocol = ntohs(eh->ether_type);



            if (e_protocol == 0x0800) {
                struct in_addr src, dest;
                struct ipv4_header *ip = (struct ipv4_header *)(buffer+14);
                src.s_addr = ip->sourceAddress;
                dest.s_addr = ip->destinationAddress;




                if (ip->protocol==IPPROTO_TCP) { //IPPROTO_TCP=6

                    struct tcp_header *tcp = (struct tcp_header *)(buffer+14+20);   // ethernet_header 14 byte + ipv4_header 20byte
                    printf(GREEN "[TCP] " RESET "%s:%d -> %s:%d\n",inet_ntoa(src), ntohs(tcp->sourcePort), inet_ntoa(dest), ntohs(tcp->destinationPort));

                }
                if (ip->protocol==IPPROTO_UDP) { // IPPROTO_UDP=17

                    struct udp_header *udp = (struct udp_header *)(buffer+14+20);
                    printf(BLUE "[UDP] " RESET "%s:%d -> %s:%d\n", inet_ntoa(src) , ntohs(udp->sourcePort) , inet_ntoa(dest) , ntohs(udp->destinationPort));

                }

            }

            if (e_protocol == 0x86DD) {
                struct ipv6_header *ipv6 = (struct ipv6_header *)(buffer+14);
                char src_ip[INET6_ADDRSTRLEN];
                char dest_ip[INET6_ADDRSTRLEN];

                inet_ntop(AF_INET6, ipv6->sourceAddress, src_ip, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, ipv6->destinationAddress, dest_ip, INET6_ADDRSTRLEN);




                if (ipv6->nextHeader==IPPROTO_TCP) { //IPPROTO_TCP=6

                    struct tcp_header *tcp = (struct tcp_header *)(buffer+14+40);   // ethernet_header 14 byte + ipv6_header 40byte
                    printf(GREEN "[TCP] " RESET "%s:%d -> %s:%d\n",src_ip, ntohs(tcp->sourcePort), dest_ip, ntohs(tcp->destinationPort));

                }
                if (ipv6->nextHeader==IPPROTO_UDP) { // IPPROTO_UDP=17

                    struct udp_header *udp = (struct udp_header *)(buffer+14+40);
                    printf(BLUE "[UDP-v6] " RESET "%s:%d -> %s:%d\n",src_ip, ntohs(udp->sourcePort),dest_ip, ntohs(udp->destinationPort));

                }

            }

            printf("\n");

        }

    }

    return 0;
}