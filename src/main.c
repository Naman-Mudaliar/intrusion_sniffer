#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sniff.h"

#define MAX_BLACKLIST 32
#define DEFAULT_QUEUE 4096

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s [-i IFACE | -r FILE.pcap] [-w WORKERS] [-q QUEUE] [-b HOST]... [-v]\n\n"
          "  -i IFACE   interface to sniff (default eth0; usually needs root)\n"
          "  -r FILE    replay a saved capture instead (no root needed)\n"
          "  -w N       worker threads (default: number of CPUs)\n"
          "  -q N       packet queue capacity (default %d)\n"
          "  -b HOST    blacklist a Host header value (repeatable; default\n"
          "             www.google.co.uk and www.facebook.com)\n"
          "  -v         print one line per packet\n",
          prog, DEFAULT_QUEUE);
}

static int parse_positive(const char *s, long max, long *out) {
  char *end;
  long v = strtol(s, &end, 10);
  if (*s == '\0' || *end != '\0' || v < 1 || v > max) {
    return -1;
  }
  *out = v;
  return 0;
}

int main(int argc, char *argv[]) {
  static const char *default_bl[] = {"www.google.co.uk", "www.facebook.com"};
  const char *bl[MAX_BLACKLIST];
  size_t nbl = 0;

  long cpus = sysconf(_SC_NPROCESSORS_ONLN);
  sniff_opts o = {
      .iface = "eth0",
      .pcap_file = NULL,
      .verbose = 0,
      .workers = (cpus < 1) ? 1 : (cpus > 64 ? 64 : (int)cpus),
      .queue_capacity = DEFAULT_QUEUE,
  };

  static const struct option long_opts[] = {
      {"interface", required_argument, NULL, 'i'},
      {"read", required_argument, NULL, 'r'},
      {"workers", required_argument, NULL, 'w'},
      {"queue", required_argument, NULL, 'q'},
      {"blacklist", required_argument, NULL, 'b'},
      {"verbose", no_argument, NULL, 'v'},
      {NULL, 0, NULL, 0} /* terminator: getopt_long requires it */
  };

  int c;
  long n;
  while ((c = getopt_long(argc, argv, "i:r:w:q:b:v", long_opts, NULL)) != -1) {
    switch (c) {
      case 'i': o.iface = optarg; break;
      case 'r': o.pcap_file = optarg; break;
      case 'v': o.verbose = 1; break;
      case 'w':
        if (parse_positive(optarg, 256, &n) != 0) { usage(argv[0]); return 2; }
        o.workers = (int)n;
        break;
      case 'q':
        if (parse_positive(optarg, 1000000, &n) != 0) { usage(argv[0]); return 2; }
        o.queue_capacity = (size_t)n;
        break;
      case 'b':
        if (nbl == MAX_BLACKLIST) {
          fprintf(stderr, "too many -b entries (max %d)\n", MAX_BLACKLIST);
          return 2;
        }
        bl[nbl++] = optarg;
        break;
      default:
        usage(argv[0]);
        return 2;
    }
  }

  if (nbl == 0) {
    o.blacklist = default_bl;
    o.nblacklist = 2;
  } else {
    o.blacklist = bl;
    o.nblacklist = nbl;
  }
  return sniff_run(&o);
}
