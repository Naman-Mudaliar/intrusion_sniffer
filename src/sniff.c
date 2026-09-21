#include "sniff.h"

#include <pcap.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>

#include "detect.h"
#include "pool.h"
#include "queue.h"

static pcap_t *volatile g_handle = NULL;

static void on_signal(int sig) {
  (void)sig;
  pcap_t *h = g_handle;
  if (h != NULL) {
    pcap_breakloop(h);
  }
}

typedef struct {
  queue *q;
  int block; /* replaying a file: wait for space instead of dropping */
} capture_ctx;

static void on_packet(unsigned char *user, const struct pcap_pkthdr *hdr,
                      const unsigned char *bytes) {
  capture_ctx *c = (capture_ctx *)user;
  queue_push(c->q, bytes, hdr->caplen, c->block); /* drops are counted inside */
}

static void print_report(detector *d, queue *q, pcap_t *h, int live) {
  ids_stats s;
  detector_snapshot(d, &s);

  printf("\n===== Intrusion Detection Report =====\n");
  printf("%llu SYN packets detected from %llu different IPs (syn attack)\n",
         (unsigned long long)s.syn_packets, (unsigned long long)s.unique_syn_ips);
  printf("%llu ARP responses (cache poisoning)\n", (unsigned long long)s.arp_replies);
  printf("%llu URL blacklist violations", (unsigned long long)s.blacklist_hits);
  size_t n = detector_blacklist_size(d);
  for (size_t i = 0; i < n; i++) {
    printf("%s%llu %s", i == 0 ? " (" : ", ",
           (unsigned long long)detector_blacklist_entry_hits(d, i),
           detector_blacklist_name(d, i));
  }
  printf("%s\n", n ? ")" : "");
  printf("%llu malformed packets\n", (unsigned long long)s.malformed_packets);
  printf("%llu packets dropped (queue full)\n", (unsigned long long)queue_dropped(q));
  if (s.ipset_failures) {
    printf("%llu SYN source IPs not recorded (out of memory)\n",
           (unsigned long long)s.ipset_failures);
  }
  if (live) {
    struct pcap_stat ps;
    if (pcap_stats(h, &ps) == 0) {
      printf("kernel: %u packets received, %u dropped\n", ps.ps_recv, ps.ps_drop);
    }
  }
  printf("======================================\n");
}

int sniff_run(const sniff_opts *o) {
  char errbuf[PCAP_ERRBUF_SIZE];
  int live = (o->pcap_file == NULL);

  pcap_t *h = live ? pcap_open_live(o->iface, SNAPLEN, 1, 1000, errbuf)
                   : pcap_open_offline(o->pcap_file, errbuf);
  if (h == NULL) {
    fprintf(stderr, "Unable to open %s: %s\n", live ? o->iface : o->pcap_file, errbuf);
    if (live) {
      fprintf(stderr, "(live capture usually needs root; try -r FILE to replay a capture)\n");
    }
    return 1;
  }

  detector *d = detector_new(o->blacklist, o->nblacklist);
  queue *q = queue_new(o->queue_capacity);
  pool *p = (d && q) ? pool_start(q, d, o->workers, o->verbose) : NULL;
  if (p == NULL) {
    fprintf(stderr, "Failed to initialise (out of memory or thread creation failed)\n");
    queue_free(q);
    detector_free(d);
    pcap_close(h);
    return 1;
  }

  struct sigaction sa = {0};
  sa.sa_handler = on_signal; /* no SA_RESTART, so a blocked read is interrupted */
  sigemptyset(&sa.sa_mask);
  g_handle = h;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  printf("Capturing on %s (%d workers, queue %zu). Ctrl+C to stop.\n",
         live ? o->iface : o->pcap_file, o->workers, o->queue_capacity);

  capture_ctx ctx = {.q = q, .block = !live};
  pcap_loop(h, -1, on_packet, (unsigned char *)&ctx);
  g_handle = NULL;

  /* Shutdown order matters: stop feeding, let workers drain, THEN report. */
  queue_close(q);
  pool_join(p);
  print_report(d, q, h, live);

  queue_free(q);
  detector_free(d);
  pcap_close(h);
  return 0;
}
