#include "parse.h"

#include <string.h>

#define ETH_LEN 14
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define ARP_LEN 28 /* Ethernet/IPv4 ARP body */
#define ARP_OP_REPLY 2
#define IP_MIN_HDR 20
#define TCP_MIN_HDR 20
#define IPPROTO_TCP_NUM 6
#define IP_FRAG_OFFSET_MASK 0x1FFF

static uint16_t rd16(const uint8_t *p) {
  return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

pkt_kind parse_packet(const uint8_t *buf, size_t caplen, parsed_pkt *out) {
  memset(out, 0, sizeof *out);
  out->kind = PKT_IGNORED;

  if (caplen < ETH_LEN) {
    return out->kind = PKT_MALFORMED;
  }
  uint16_t ethertype = rd16(buf + 12);

  if (ethertype == ETHERTYPE_ARP) {
    if (caplen < ETH_LEN + ARP_LEN) {
      return out->kind = PKT_MALFORMED;
    }
    /* ARP body: htype(2) ptype(2) hlen(1) plen(1) oper(2) ... */
    if (rd16(buf + ETH_LEN + 6) == ARP_OP_REPLY) {
      out->kind = PKT_ARP_REPLY;
    }
    return out->kind;
  }

  if (ethertype != ETHERTYPE_IPV4) {
    return out->kind; /* IGNORED */
  }

  /* ---- IPv4 ---- */
  if (caplen < ETH_LEN + IP_MIN_HDR) {
    return out->kind = PKT_MALFORMED;
  }
  const uint8_t *ip = buf + ETH_LEN;
  size_t avail = caplen - ETH_LEN;

  if ((ip[0] >> 4) != 4) {
    return out->kind = PKT_MALFORMED;
  }
  size_t ihl = (size_t)(ip[0] & 0x0F) * 4;
  if (ihl < IP_MIN_HDR || ihl > avail) {
    return out->kind = PKT_MALFORMED;
  }
  size_t total = rd16(ip + 2);
  if (total < ihl) {
    return out->kind = PKT_MALFORMED;
  }
  if (total > avail) {
    total = avail; /* capture was truncated (snaplen); use what we have */
  }

  if (ip[9] != IPPROTO_TCP_NUM) {
    return out->kind; /* IGNORED */
  }
  if (rd16(ip + 6) & IP_FRAG_OFFSET_MASK) {
    return out->kind; /* non-first fragment: no TCP header inside */
  }

  /* ---- TCP ---- */
  const uint8_t *tcp = ip + ihl;
  size_t tavail = total - ihl;
  if (tavail < TCP_MIN_HDR) {
    return out->kind = PKT_MALFORMED;
  }
  size_t thl = (size_t)(tcp[12] >> 4) * 4;
  if (thl < TCP_MIN_HDR || thl > tavail) {
    return out->kind = PKT_MALFORMED;
  }

  out->src_ip = rd32(ip + 12);
  out->dst_ip = rd32(ip + 16);
  out->dst_port = rd16(tcp + 2);
  out->tcp_flags = tcp[13];
  out->payload = tcp + thl;
  out->payload_len = tavail - thl;
  out->kind = PKT_TCP;
  return out->kind;
}
