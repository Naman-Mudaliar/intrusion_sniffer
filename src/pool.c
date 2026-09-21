#include "pool.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "parse.h"

struct pool {
  pthread_t *tids;
  int n;
  queue *q;
  detector *d;
  int verbose;
};

static void ip_str(uint32_t host_order, char *buf, size_t n) {
  struct in_addr a = {.s_addr = htonl(host_order)};
  if (inet_ntop(AF_INET, &a, buf, (socklen_t)n) == NULL) {
    buf[0] = '?';
    buf[1] = '\0';
  }
}

static void *worker(void *arg) {
  pool *p = arg;
  job j;
  while (queue_pop(p->q, &j)) {
    parsed_pkt pkt;
    parse_packet(j.data, j.caplen, &pkt);
    int m = detector_handle(p->d, &pkt);

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    if (m >= 0) {
      ip_str(pkt.src_ip, src, sizeof src);
      ip_str(pkt.dst_ip, dst, sizeof dst);
      /* one printf per event so lines from different workers do not interleave */
      printf("Blacklisted URL violation: %s -> %s (%s)\n", src, dst,
             detector_blacklist_name(p->d, (size_t)m));
    } else if (p->verbose) {
      if (pkt.kind == PKT_TCP) {
        ip_str(pkt.src_ip, src, sizeof src);
        ip_str(pkt.dst_ip, dst, sizeof dst);
        printf("TCP %s -> %s:%u flags=0x%02x payload=%zu\n", src, dst,
               (unsigned)pkt.dst_port, (unsigned)pkt.tcp_flags, pkt.payload_len);
      } else if (pkt.kind == PKT_ARP_REPLY) {
        printf("ARP reply\n");
      } else if (pkt.kind == PKT_MALFORMED) {
        printf("malformed packet (%u bytes captured)\n", (unsigned)j.caplen);
      }
    }
  }
  return NULL;
}

pool *pool_start(queue *q, detector *d, int nworkers, int verbose) {
  if (nworkers < 1) {
    return NULL;
  }
  pool *p = calloc(1, sizeof *p);
  if (p == NULL) {
    return NULL;
  }
  p->tids = calloc((size_t)nworkers, sizeof *p->tids);
  if (p->tids == NULL) {
    free(p);
    return NULL;
  }
  p->q = q;
  p->d = d;
  p->verbose = verbose;

  for (int i = 0; i < nworkers; i++) {
    if (pthread_create(&p->tids[i], NULL, worker, p) != 0) {
      /* stop and reap the workers that did start */
      queue_close(q);
      for (int k = 0; k < i; k++) {
        pthread_join(p->tids[k], NULL);
      }
      free(p->tids);
      free(p);
      return NULL;
    }
    p->n = i + 1;
  }
  return p;
}

void pool_join(pool *p) {
  if (p == NULL) {
    return;
  }
  for (int i = 0; i < p->n; i++) {
    pthread_join(p->tids[i], NULL);
  }
  free(p->tids);
  free(p);
}
