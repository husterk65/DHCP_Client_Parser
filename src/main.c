#include <stdio.h>
#include "dhcp_client.h"
#include <sys/socket.h>
#include <net/if.h>
#include <linux/socket.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1]; // interface name
    // Currently using hardcode to represent mac address
    unsigned char mac[6] = {0xf0, 0xa6, 0x54, 0x5e, 0xb4, 0xff};
    printf("Using fixed MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // Create socket IPv4 UDP
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    // Configure socket
    int enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable));
    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname));

    // Configure client addr
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;               // IPv4
    client_addr.sin_port = htons(DHCP_CLIENT_PORT); // 68
    client_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0)
    {
        perror("bind");
        return 1;
    }

    // Configure server addr
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT); // 67
    server_addr.sin_addr.s_addr = INADDR_BROADCAST;

    printf("Sending DHCP DISCOVER...\n");
    uint32_t xid = rand();
    send_discover(sock, &server_addr, mac, xid);

    char buf[1500]; // buffer to receive message
    while (1)
    {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr *)&src, &slen);
        if (n <= 0)
            continue;

        struct dhcp_packet *pkt = (struct dhcp_packet *)buf;
        //ntohl used to convert network edian => host edian
        if (ntohl(pkt->xid) != xid)
            continue;
        if (ntohl(pkt->magic_cookie) != DHCP_MAGIC_COOKIE)
            continue;

        uint8_t type = 0;
        uint32_t server_id = 0;
        for (int i = 0; i < sizeof(pkt->options);)
        {
            uint8_t code = pkt->options[i++];
            if (code == 0xFF)
                break;
            if (code == 0)
                continue;
            uint8_t len_opt = pkt->options[i++];
            if (code == 53)
            {
                type = pkt->options[i];
            }

            if (code == 54)
            {
                memcpy(&server_id, &pkt->options[i], 4);
            }

            i += len_opt;
        }

        if (type == DHCPOFFER)
        {
            printf("Got DHCP OFFER: %s\n", inet_ntoa(*(struct in_addr *)&pkt->yiaddr));
            dump_packet(pkt, n);
            printf("Sending DHCP REQUEST...\n");
            send_request(sock, &server_addr, mac, xid, server_id, pkt->yiaddr);
            continue;
        }

        if (type == DHCPACK)
        {
            printf("Got DHCP ACK: %s\n", inet_ntoa(*(struct in_addr *)&pkt->yiaddr));
            break;
        }
    }
    return 1;
}