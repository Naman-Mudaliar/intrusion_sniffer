#include <stdlib.h>

#include "check.h"
#include "frames.h"
#include "parse.h"

#define SYN TCP_FLAG_SYN
#define ACK TCP_FLAG_ACK

static uint8_t f[2048];

static void test_valid_syn(void) {
  parsed_pkt p;
  size_t n = build_tcp_frame(f, IP(10, 0, 0, 5), IP(10, 0, 0, 9), 80, SYN, 5, 5, NULL);
  CHECK(parse_packet(f, n, &p) == PKT_TCP);
  CHECK(p.src_ip == IP(10, 0, 0, 5));
  CHECK(p.dst_ip == IP(10, 0, 0, 9));
  CHECK(p.dst_port == 80);
  CHECK(p.tcp_flags == SYN);
  CHECK(p.payload_len == 0);
}

static void test_flags_preserved(void) {
  parsed_pkt p;
  size_t n = build_tcp_frame(f, 1, 2, 80, SYN | ACK, 5, 5, NULL);
  CHECK(parse_packet(f, n, &p) == PKT_TCP);
  CHECK(p.tcp_flags == (SYN | ACK));
}

static void test_payload_and_options(void) {
  parsed_pkt p;
  const char *body = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
  /* IP options (ihl=7) and TCP options (data offset 8) must shift the payload correctly */
  size_t n = build_tcp_frame(f, 1, 2, 80, ACK, 7, 8, body);
  CHECK(parse_packet(f, n, &p) == PKT_TCP);
  CHECK(p.payload_len == strlen(body));
  CHECK(memcmp(p.payload, body, strlen(body)) == 0);
}

static void test_arp(void) {
  parsed_pkt p;
  size_t n = build_arp_frame(f, 2);
  CHECK(parse_packet(f, n, &p) == PKT_ARP_REPLY);
  n = build_arp_frame(f, 1); /* request */
  CHECK(parse_packet(f, n, &p) == PKT_IGNORED);
}

static void test_ignored(void) {
  parsed_pkt p;
  size_t n = build_tcp_frame(f, 1, 2, 80, SYN, 5, 5, NULL);
  put16(f + 12, 0x86DD); /* IPv6 */
  CHECK(parse_packet(f, n, &p) == PKT_IGNORED);

  n = build_tcp_frame(f, 1, 2, 80, SYN, 5, 5, NULL);
  f[14 + 9] = 17; /* UDP */
  CHECK(parse_packet(f, n, &p) == PKT_IGNORED);

  n = build_tcp_frame(f, 1, 2, 80, SYN, 5, 5, NULL);
  put16(f + 14 + 6, 0x0010); /* fragment offset != 0: no TCP header inside */
  CHECK(parse_packet(f, n, &p) == PKT_IGNORED);
}

static void test_malformed(void) {
  parsed_pkt p;
  size_t n = build_tcp_frame(f, 1, 2, 80, SYN, 5, 5, NULL);
  uint8_t g[2048];

  CHECK(parse_packet(f, 5, &p) == PKT_MALFORMED);   /* shorter than an Ethernet header */
  CHECK(parse_packet(f, 14 + 10, &p) == PKT_MALFORMED); /* shorter than an IP header */

  memcpy(g, f, n); g[14] = 0x44; /* ihl = 4 words (< 5) */
  CHECK(parse_packet(g, n, &p) == PKT_MALFORMED);

  memcpy(g, f, n); g[14] = 0x65; /* version 6 in an IPv4 ethertype */
  CHECK(parse_packet(g, n, &p) == PKT_MALFORMED);

  memcpy(g, f, n); g[14] = 0x4F; /* ihl = 15 words = 60 bytes, more than captured after eth */
  CHECK(parse_packet(g, 14 + 40, &p) == PKT_MALFORMED);

  memcpy(g, f, n); put16(g + 14 + 2, 10); /* total length smaller than the IP header */
  CHECK(parse_packet(g, n, &p) == PKT_MALFORMED);

  memcpy(g, f, n); g[14 + 20 + 12] = 0x40; /* TCP data offset 4 words (< 5) */
  CHECK(parse_packet(g, n, &p) == PKT_MALFORMED);

  memcpy(g, f, n); g[14 + 20 + 12] = 0xF0; /* TCP header claims 60 bytes, only 20 exist */
  CHECK(parse_packet(g, n, &p) == PKT_MALFORMED);

  CHECK(parse_packet(f, 14 + 20 + 10, &p) == PKT_MALFORMED); /* TCP header cut short */
}

/* A capture cut by snaplen (IP total length > captured bytes) must be clamped, not over-read. */
static void test_snaplen_truncated_payload(void) {
  parsed_pkt p;
  size_t n = build_tcp_frame(f, 1, 2, 80, ACK, 5, 5, "0123456789");
  CHECK(parse_packet(f, n - 4, &p) == PKT_TCP);
  CHECK(p.payload_len == 6);
}

/* Every prefix of a valid frame, each in an exact-size heap buffer so ASan
 * flags any read past the end. Must never crash. */
static void test_truncation_sweep(void) {
  const char *body = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
  size_t full = build_tcp_frame(f, 1, 2, 80, SYN, 6, 6, body);
  for (size_t n = 0; n <= full; n++) {
    uint8_t *exact = malloc(n ? n : 1);
    memcpy(exact, f, n);
    parsed_pkt p;
    pkt_kind k = parse_packet(exact, n, &p);
    if (k == PKT_TCP) {
      CHECK(p.payload_len <= n); /* payload can never exceed what was captured */
      CHECK(p.payload_len == 0 || (p.payload >= exact && p.payload + p.payload_len <= exact + n));
    }
    free(exact);
  }
  full = build_arp_frame(f, 2);
  for (size_t n = 0; n <= full; n++) {
    uint8_t *exact = malloc(n ? n : 1);
    memcpy(exact, f, n);
    parsed_pkt p;
    parse_packet(exact, n, &p);
    free(exact);
  }
}

/* Random garbage with a fixed seed: must never crash or read out of bounds. */
static void test_random_bytes(void) {
  uint32_t s = 12345;
  for (int i = 0; i < 100000; i++) {
    s ^= s << 13; s ^= s >> 17; s ^= s << 5; /* xorshift32 */
    size_t n = s % 200;
    uint8_t *b = malloc(n ? n : 1);
    for (size_t k = 0; k < n; k++) {
      s ^= s << 13; s ^= s >> 17; s ^= s << 5;
      b[k] = (uint8_t)s;
    }
    if (n >= 14 && (i & 1)) { /* bias half of them toward reaching the IPv4/TCP code */
      put16(b + 12, 0x0800);
      if (n > 14) b[14] = (uint8_t)(0x40 | (b[14] & 0x0F));
      if (n > 23) b[23] = 6;
    }
    parsed_pkt p;
    parse_packet(b, n, &p);
    free(b);
  }
}

int main(void) {
  test_valid_syn();
  test_flags_preserved();
  test_payload_and_options();
  test_arp();
  test_ignored();
  test_malformed();
  test_snaplen_truncated_payload();
  test_truncation_sweep();
  test_random_bytes();
  return TEST_RESULT();
}
