#include "detect.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "ipset.h"

struct detector {
  pthread_mutex_t lock;
  ipset *ips;
  uint64_t syn, arp, malformed, bl_total, ipset_failures;
  size_t nbl;
  char **bl;          /* immutable after construction, so read without the lock */
  uint64_t *bl_hits;  /* guarded by lock */
};

detector *detector_new(const char *const *blacklist, size_t n) {
  detector *d = calloc(1, sizeof *d);
  if (d == NULL) {
    return NULL;
  }
  d->ips = ipset_new();
  d->bl = calloc(n ? n : 1, sizeof *d->bl);
  d->bl_hits = calloc(n ? n : 1, sizeof *d->bl_hits);
  if (d->ips == NULL || d->bl == NULL || d->bl_hits == NULL) {
    goto fail;
  }
  for (size_t i = 0; i < n; i++) {
    d->bl[i] = strdup(blacklist[i]);
    if (d->bl[i] == NULL) {
      d->nbl = i;
      goto fail;
    }
  }
  d->nbl = n;
  pthread_mutex_init(&d->lock, NULL);
  return d;

fail:
  ipset_free(d->ips);
  if (d->bl != NULL) {
    for (size_t i = 0; i < d->nbl; i++) {
      free(d->bl[i]);
    }
  }
  free(d->bl);
  free(d->bl_hits);
  free(d);
  return NULL;
}

int http_find_host(const uint8_t *payload, size_t len, const char **val, size_t *vlen) {
  size_t pos = 0;
  while (pos < len) {
    const uint8_t *nl = memchr(payload + pos, '\n', len - pos);
    size_t end = nl ? (size_t)(nl - payload) : len;
    size_t line_len = end - pos;
    const char *line = (const char *)payload + pos;

    /* strip trailing CR to detect the blank line that ends the headers */
    size_t trimmed = line_len;
    if (trimmed > 0 && line[trimmed - 1] == '\r') {
      trimmed--;
    }
    if (trimmed == 0) {
      return 0; /* end of headers, no Host seen */
    }
    if (trimmed >= 5 && strncasecmp(line, "host:", 5) == 0) {
      const char *v = line + 5;
      size_t n = trimmed - 5;
      while (n > 0 && (*v == ' ' || *v == '\t')) {
        v++;
        n--;
      }
      while (n > 0 && (v[n - 1] == ' ' || v[n - 1] == '\t')) {
        n--;
      }
      /* strip a trailing ":port" */
      size_t k = n;
      while (k > 0 && v[k - 1] >= '0' && v[k - 1] <= '9') {
        k--;
      }
      if (k > 0 && k < n && v[k - 1] == ':') {
        n = k - 1;
      }
      *val = v;
      *vlen = n;
      return n > 0;
    }
    pos = end + 1;
  }
  return 0;
}

static int blacklist_match(const detector *d, const parsed_pkt *p) {
  if (p->dst_port != 80 || p->payload_len == 0) {
    return -1;
  }
  const char *host;
  size_t hlen;
  if (!http_find_host(p->payload, p->payload_len, &host, &hlen)) {
    return -1;
  }
  for (size_t i = 0; i < d->nbl; i++) {
    /* exact host match: "www.google.co.uk.evil.net" must not match */
    if (strlen(d->bl[i]) == hlen && strncasecmp(d->bl[i], host, hlen) == 0) {
      return (int)i;
    }
  }
  return -1;
}

int detector_handle(detector *d, const parsed_pkt *p) {
  switch (p->kind) {
    case PKT_MALFORMED:
      pthread_mutex_lock(&d->lock);
      d->malformed++;
      pthread_mutex_unlock(&d->lock);
      return -1;

    case PKT_ARP_REPLY:
      pthread_mutex_lock(&d->lock);
      d->arp++;
      pthread_mutex_unlock(&d->lock);
      return -1;

    case PKT_TCP: {
      /* SYN without ACK = connection attempt. SYN-ACKs are normal replies. */
      if ((p->tcp_flags & TCP_FLAG_SYN) && !(p->tcp_flags & TCP_FLAG_ACK)) {
        pthread_mutex_lock(&d->lock);
        d->syn++;
        if (ipset_add(d->ips, p->src_ip) < 0) {
          d->ipset_failures++;
        }
        pthread_mutex_unlock(&d->lock);
      }
      int m = blacklist_match(d, p);
      if (m >= 0) {
        pthread_mutex_lock(&d->lock);
        d->bl_total++;
        d->bl_hits[m]++;
        pthread_mutex_unlock(&d->lock);
      }
      return m;
    }

    case PKT_IGNORED:
    default:
      return -1;
  }
}

void detector_snapshot(detector *d, ids_stats *out) {
  pthread_mutex_lock(&d->lock);
  out->syn_packets = d->syn;
  out->unique_syn_ips = ipset_count(d->ips);
  out->arp_replies = d->arp;
  out->malformed_packets = d->malformed;
  out->blacklist_hits = d->bl_total;
  out->ipset_failures = d->ipset_failures;
  pthread_mutex_unlock(&d->lock);
}

size_t detector_blacklist_size(const detector *d) { return d->nbl; }

const char *detector_blacklist_name(const detector *d, size_t i) {
  return i < d->nbl ? d->bl[i] : NULL;
}

uint64_t detector_blacklist_entry_hits(detector *d, size_t i) {
  if (i >= d->nbl) {
    return 0;
  }
  pthread_mutex_lock(&d->lock);
  uint64_t h = d->bl_hits[i];
  pthread_mutex_unlock(&d->lock);
  return h;
}

void detector_free(detector *d) {
  if (d == NULL) {
    return;
  }
  pthread_mutex_destroy(&d->lock);
  ipset_free(d->ips);
  for (size_t i = 0; i < d->nbl; i++) {
    free(d->bl[i]);
  }
  free(d->bl);
  free(d->bl_hits);
  free(d);
}
