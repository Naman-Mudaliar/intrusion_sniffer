#ifndef DETECT_H
#define DETECT_H

#include <stddef.h>
#include <stdint.h>

#include "parse.h"

/*
 * Detector: holds all detection state behind one mutex. Safe to call from
 * many worker threads. Detects:
 *   - SYN floods (counts SYN-without-ACK packets and distinct source IPs)
 *   - ARP replies (cache-poisoning indicator)
 *   - HTTP requests (port 80) whose Host header is on a blacklist
 */

typedef struct detector detector;

typedef struct {
  uint64_t syn_packets;
  uint64_t unique_syn_ips;
  uint64_t arp_replies;
  uint64_t malformed_packets;
  uint64_t blacklist_hits;
  uint64_t ipset_failures;   /* SYN source IPs we could not record (out of memory) */
} ids_stats;

/* Blacklist entries are copied. NULL on allocation failure. */
detector *detector_new(const char *const *blacklist, size_t n);

/* Updates counters for one parsed packet. Returns the index of the matched
 * blacklist entry, or -1 if the packet did not match any. */
int detector_handle(detector *d, const parsed_pkt *p);

void detector_snapshot(detector *d, ids_stats *out);
size_t detector_blacklist_size(const detector *d);
const char *detector_blacklist_name(const detector *d, size_t i);
uint64_t detector_blacklist_entry_hits(detector *d, size_t i);
void detector_free(detector *d);

/* Exposed for testing. Finds the Host header value in an HTTP request
 * payload (bounded, case-insensitive header name, stops at the blank line,
 * strips whitespace and a trailing :port). Returns 1 and sets val and vlen on success. */
int http_find_host(const uint8_t *payload, size_t len, const char **val, size_t *vlen);

#endif
