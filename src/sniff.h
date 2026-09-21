#ifndef SNIFF_H
#define SNIFF_H

#include <stddef.h>

typedef struct {
  const char *iface;       /* live capture interface (ignored if pcap_file set) */
  const char *pcap_file;   /* replay a saved capture instead of sniffing live */
  int verbose;
  int workers;
  size_t queue_capacity;
  const char *const *blacklist;
  size_t nblacklist;
} sniff_opts;

/* Captures until Ctrl+C (live) or end of file (replay), then drains the
 * queue, joins the workers and prints the report. Returns 0 on success. */
int sniff_run(const sniff_opts *opts);

#endif
