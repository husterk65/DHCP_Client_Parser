#include "dhcp_client.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>

static void add_option(uint8_t *opts, int *idx, uint8_t code, uint8_t len, const void *data)
{
  opts[(*idx)++] = code;
  opts[(*idx)++] = len;
  memcpy(opts + *idx, data, len);
  *idx += len;
}

int send_discover(int sock, struct sockaddr_in *addr, uint8_t *mac, uint32_t xid)
{
  struct dhcp_packet pkt = {0};
  pkt.op = 1; // request
  pkt.htype = 1;
  pkt.hlen = 6;
  pkt.xid = htonl(xid);
  pkt.flags = htons(0x8000);
  memcpy(pkt.chaddr, mac, 6);
  pkt.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

  int idx = 0;
  uint8_t type = DHCPDISCOVER;
  add_option(pkt.options, &idx, 53, 1, &type);
  pkt.options[idx++] = 0xFF; // End options

  return sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)addr, sizeof(*addr));
}

int send_request(int sock, struct sockaddr_in *addr, uint8_t *mac, uint32_t xid,
                 uint32_t server_ip, uint32_t offered_ip)
{
  struct dhcp_packet pkt = {0};
  pkt.op = 1;
  pkt.htype = 1;
  pkt.hlen = 6;
  pkt.xid = htonl(xid);
  pkt.flags = htons(0x8000);
  memcpy(pkt.chaddr, mac, 6);
  pkt.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

  int idx = 0;
  uint8_t type = DHCPREQUEST;
  add_option(pkt.options, &idx, 53, 1, &type);
  add_option(pkt.options, &idx, 50, 4, &offered_ip);
  add_option(pkt.options, &idx, 54, 4, &server_ip);
  pkt.options[idx++] = 0xFF; // Endd options

  return sendto(sock, &pkt, sizeof(pkt), 0, (struct sockaddr *)addr, sizeof(*addr));
}

void dump_packet(struct dhcp_packet *pkt, int len)
{
  printf("=== DHCP Packet Dump ===\n");
  printf("op: %u, htype: %u, hlen: %u, hops: %u\n", pkt->op, pkt->htype, pkt->hlen, pkt->hops);
  printf("xid: 0x%08X\n", ntohl(pkt->xid));
  printf("yiaddr: %s\n", inet_ntoa(*(struct in_addr *)&pkt->yiaddr));
  printf("siaddr: %s\n", inet_ntoa(*(struct in_addr *)&pkt->siaddr));
  printf("Magic cookie: 0x%08X\n", ntohl(pkt->magic_cookie));

  uint8_t *opt_ptr = pkt->options;
  for (int i = 0; i < sizeof(pkt->options);)
  {
    uint8_t code = opt_ptr[i++];
    if (code == 0xFF)
    {
      printf("Option End\n");
      break;
    }

    if (code == 0)
      continue;
    uint8_t len_opt = opt_ptr[i++];
    printf("Option %u (%u bytes): ", code, len_opt);
    for (int j = 0; j < len_opt; j++)
      printf("%02X ", opt_ptr[i + j]);
    printf("\n");
    i += len_opt;
  }
  printf("======================\n");
}