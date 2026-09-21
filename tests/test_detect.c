#include <pthread.h>
#include <string.h>

#include "check.h"
#include "detect.h"
#include "frames.h"
#include "parse.h"

static const char *BL[] = {"www.example.com", "bad.test"};

static int feed(detector *d, const uint8_t *frame, size_t n) {
  parsed_pkt p;
  parse_packet(frame, n, &p);
  return detector_handle(d, &p);
}

static void test_syn_counting(void) {
  detector *d = detector_new(BL, 2);
  uint8_t f[2048];
  size_t n;

  n = build_tcp_frame(f, IP(1, 1, 1, 1), IP(9, 9, 9, 9), 80, TCP_FLAG_SYN, 5, 5, NULL);
  feed(d, f, n);
  feed(d, f, n); /* same source again */
  n = build_tcp_frame(f, IP(2, 2, 2, 2), IP(9, 9, 9, 9), 80, TCP_FLAG_SYN, 5, 5, NULL);
  feed(d, f, n);
  /* SYN-ACK is a normal reply, not an attack packet */
  n = build_tcp_frame(f, IP(3, 3, 3, 3), IP(9, 9, 9, 9), 80, TCP_FLAG_SYN | TCP_FLAG_ACK, 5, 5, NULL);
  feed(d, f, n);
  /* plain ACK */
  n = build_tcp_frame(f, IP(4, 4, 4, 4), IP(9, 9, 9, 9), 80, TCP_FLAG_ACK, 5, 5, NULL);
  feed(d, f, n);

  ids_stats s;
  detector_snapshot(d, &s);
  CHECK(s.syn_packets == 3);
  CHECK(s.unique_syn_ips == 2);
  detector_free(d);
}

static void test_arp_and_malformed(void) {
  detector *d = detector_new(BL, 2);
  uint8_t f[2048];
  size_t n = build_arp_frame(f, 2);
  feed(d, f, n);
  feed(d, f, n);
  n = build_arp_frame(f, 1);
  feed(d, f, n);      /* request: not counted */
  feed(d, f, 5);      /* truncated: malformed */
  ids_stats s;
  detector_snapshot(d, &s);
  CHECK(s.arp_replies == 2);
  CHECK(s.malformed_packets == 1);
  detector_free(d);
}

static int http(detector *d, uint16_t port, const char *req) {
  uint8_t f[2048];
  size_t n = build_tcp_frame(f, IP(5, 5, 5, 5), IP(6, 6, 6, 6), port, TCP_FLAG_ACK, 5, 5, req);
  return feed(d, f, n);
}

static void test_blacklist(void) {
  detector *d = detector_new(BL, 2);

  CHECK(http(d, 80, "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n") == 0);
  CHECK(http(d, 80, "GET / HTTP/1.1\r\nhOsT:   WWW.Example.COM:80  \r\n\r\n") == 0); /* case, spaces, port */
  CHECK(http(d, 80, "GET / HTTP/1.1\r\nAccept: */*\r\nHost: bad.test\r\n\r\n") == 1);  /* not the first header */

  /* near misses must NOT match */
  CHECK(http(d, 80, "GET / HTTP/1.1\r\nHost: www.example.com.evil.net\r\n\r\n") == -1);
  CHECK(http(d, 80, "GET / HTTP/1.1\r\nHost: notwww.example.com\r\n\r\n") == -1);
  CHECK(http(d, 80, "GET / HTTP/1.1\r\nHost: other.org\r\n\r\n") == -1);
  CHECK(http(d, 80, "GET / HTTP/1.1\r\n\r\nHost: www.example.com\r\n") == -1); /* after headers end = body */
  CHECK(http(d, 80, "GET / HTTP/1.1\r\n\r\n") == -1);
  CHECK(http(d, 80, "garbage with no newline") == -1);
  CHECK(http(d, 80, "GET / HTTP/1.1\r\nX-Host: www.example.com\r\n\r\n") == -1);  /* different header */
  CHECK(http(d, 8080, "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n") == -1);   /* only port 80 is inspected */
  CHECK(http(d, 80, NULL) == -1);                                                  /* no payload */

  ids_stats s;
  detector_snapshot(d, &s);
  CHECK(s.blacklist_hits == 3);
  CHECK(detector_blacklist_entry_hits(d, 0) == 2);
  CHECK(detector_blacklist_entry_hits(d, 1) == 1);
  detector_free(d);
}

static void test_find_host(void) {
  const char *v;
  size_t n;
  const char *a = "GET / HTTP/1.1\r\nHost: a.b:8080\r\n\r\n";
  CHECK(http_find_host((const uint8_t *)a, strlen(a), &v, &n) == 1);
  CHECK(n == 3 && memcmp(v, "a.b", 3) == 0);
  const char *b = "Host:";
  CHECK(http_find_host((const uint8_t *)b, strlen(b), &v, &n) == 0);
  CHECK(http_find_host((const uint8_t *)"", 0, &v, &n) == 0);
}

#define THREADS 8
#define PER_THREAD 10000

static void *hammer(void *arg) {
  detector *d = ((void **)arg)[0];
  uint32_t ip = (uint32_t)(uintptr_t)((void **)arg)[1];
  uint8_t f[2048];
  size_t n = build_tcp_frame(f, ip, IP(9, 9, 9, 9), 80, TCP_FLAG_SYN, 5, 5, NULL);
  parsed_pkt p;
  parse_packet(f, n, &p);
  for (int i = 0; i < PER_THREAD; i++) {
    detector_handle(d, &p);
  }
  return NULL;
}

/* Exact totals from many threads prove the counters are properly locked (run under TSan). */
static void test_concurrent(void) {
  detector *d = detector_new(BL, 2);
  pthread_t th[THREADS];
  void *args[THREADS][2];
  for (int i = 0; i < THREADS; i++) {
    args[i][0] = d;
    args[i][1] = (void *)(uintptr_t)(100 + i);
    pthread_create(&th[i], NULL, hammer, args[i]);
  }
  for (int i = 0; i < THREADS; i++) pthread_join(th[i], NULL);
  ids_stats s;
  detector_snapshot(d, &s);
  CHECK(s.syn_packets == (uint64_t)THREADS * PER_THREAD);
  CHECK(s.unique_syn_ips == THREADS);
  detector_free(d);
}

int main(void) {
  test_syn_counting();
  test_arp_and_malformed();
  test_blacklist();
  test_find_host();
  test_concurrent();
  return TEST_RESULT();
}
