#ifndef DHCP_CLIENT_PARSER_LIB_DHCP_CLIENT
#define DHCP_CLIENT_PARSER_LIB_DHCP_CLIENT

#include <stdint.h>
#include <netinet/in.h>

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define DHCP_MAGIC_COOKIE 0x63825363 //99.130.83.99

// DHCP message types
#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPACK      5

struct dhcp_packet {
    uint8_t op, htype, hlen, hops;
    uint32_t xid;
    uint16_t secs, flags;
    uint32_t ciaddr, yiaddr, siaddr, giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint32_t magic_cookie;
    uint8_t options[308];
};

int send_discover(int sock, struct sockaddr_in *addr, uint8_t *mac, uint32_t xid);
int send_request(int sock, struct sockaddr_in *addr, uint8_t *mac, uint32_t xid,
                 uint32_t server_ip, uint32_t offered_ip);
void dump_packet(struct dhcp_packet *pkt, int len);

#endif //DHCP_CLIENT_PARSER_LIB_DHCP_CLIENT
