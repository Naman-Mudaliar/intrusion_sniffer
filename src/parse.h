#ifndef PARSE_H
#define PARSE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Pure packet parser: bytes in, result out. No globals, no pcap, no I/O.
 * Every read is bounds-checked against caplen (the number of bytes actually
 * captured), never against lengths claimed inside the packet.
 */

typedef enum {
  PKT_IGNORED,    /* valid but not something we inspect (IPv6, UDP, ...) */
  PKT_ARP_REPLY,  /* ARP reply (op == 2) */
  PKT_TCP,        /* IPv4 TCP segment, fields below are filled in */
  PKT_MALFORMED   /* truncated or internally inconsistent */
} pkt_kind;

#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_ACK 0x10

typedef struct {
  pkt_kind kind;
  uint32_t src_ip;          /* host byte order */
  uint32_t dst_ip;          /* host byte order */
  uint8_t tcp_flags;
  uint16_t dst_port;        /* host byte order */
  const uint8_t *payload;   /* points into the caller's buffer, NOT NUL-terminated */
  size_t payload_len;
} parsed_pkt;

/* Parses an Ethernet frame. Always fills *out and returns out->kind. */
pkt_kind parse_packet(const uint8_t *buf, size_t caplen, parsed_pkt *out);

#endif
