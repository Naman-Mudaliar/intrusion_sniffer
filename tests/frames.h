#ifndef FRAMES_H
#define FRAMES_H

/* Helpers that build raw Ethernet frames byte by byte. */

#include <stdint.h>
#include <string.h>

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

#define IP(a, b, c, d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

/* Builds Ethernet + IPv4 + TCP (+ payload). ihl_words / thoff_words let tests
 * create headers with options. Returns the frame length. buf must be >= 2048. */
static size_t build_tcp_frame(uint8_t *buf, uint32_t src, uint32_t dst, uint16_t dport,
                              uint8_t flags, unsigned ihl_words, unsigned thoff_words,
                              const char *payload) {
  size_t plen = payload ? strlen(payload) : 0;
  size_t ihl = ihl_words * 4, thl = thoff_words * 4;
  memset(buf, 0, 2048);
  put16(buf + 12, 0x0800);
  uint8_t *ip = buf + 14;
  ip[0] = (uint8_t)(0x40 | ihl_words);
  put16(ip + 2, (uint16_t)(ihl + thl + plen));
  ip[8] = 64;
  ip[9] = 6;
  put32(ip + 12, src);
  put32(ip + 16, dst);
  uint8_t *tcp = ip + ihl;
  put16(tcp, 40000);
  put16(tcp + 2, dport);
  tcp[12] = (uint8_t)(thoff_words << 4);
  tcp[13] = flags;
  if (plen) memcpy(tcp + thl, payload, plen);
  return 14 + ihl + thl + plen;
}

static size_t build_arp_frame(uint8_t *buf, uint16_t op) {
  memset(buf, 0, 2048);
  put16(buf + 12, 0x0806);
  put16(buf + 14, 1);       /* htype ethernet */
  put16(buf + 16, 0x0800);  /* ptype ipv4 */
  buf[18] = 6; buf[19] = 4;
  put16(buf + 20, op);
  return 14 + 28;
}

#endif
