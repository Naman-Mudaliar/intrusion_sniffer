# idsniff

A small multithreaded network intrusion detector in C (libpcap + pthreads). It watches IPv4/TCP and ARP traffic and reports:

- **SYN floods**: SYN packets (without ACK) and the number of distinct source IPs
- **ARP replies**: an indicator of ARP cache poisoning
- **Blacklisted sites**: HTTP requests to port 80 whose `Host` header is on a blacklist

Capture happens on one thread, packets go through a bounded queue to a pool of worker threads, and a final report is printed on shutdown.

## Build and run

Needs `gcc`, `make` and libpcap headers (`sudo apt install libpcap-dev`).

```
make                                   # builds build/idsniff
sudo ./build/idsniff -i eth0           # live capture, Ctrl+C prints the report
./build/idsniff -r examples/sample.pcap   # replay a capture, no root needed
```

Options: `-i IFACE`, `-r FILE`, `-w WORKERS`, `-q QUEUE_SIZE`, `-b HOST` (repeatable), `-v`.
`python3 examples/make_sample_pcap.py` regenerates the sample capture (300-source SYN flood, ARP replies, blacklisted requests, a near-miss host, noise, a truncated frame).

## Tests

```
make test    # unit tests, no root or network needed
make asan    # same tests under AddressSanitizer + UBSan
make tsan    # same tests under ThreadSanitizer
```

Tests build raw packets byte by byte and feed them to the parser, so they need no live capture. They cover: valid frames, IP/TCP options, every malformed-header case, a **truncation sweep** (every prefix of a valid frame, in an exact-size heap buffer so ASan catches any over-read), 100k random buffers, the hash set (resizes, `0.0.0.0`), the queue (full, FIFO, wrap-around, close and drain, blocking push, 4-consumer stress) and the detector (SYN vs SYN-ACK, blacklist near-misses, 8 threads hammering the counters).

## Layout

| File | Job |
|---|---|
| `src/parse.c` | Pure, bounds-checked Ethernet/IPv4/TCP/ARP parser. No globals, no I/O. |
| `src/ipset.c` | Open-addressing hash set of IPv4 addresses. |
| `src/queue.c` | Bounded MPMC packet queue with close/drain. |
| `src/detect.c` | Detection state behind one mutex; Host header matching. |
| `src/pool.c` | Joinable worker threads. |
| `src/sniff.c` | pcap setup, signal handling, ordered shutdown, report. |
| `src/main.c` | Command-line parsing. |

## Provenance

This project started as an individual systems-module coursework (a packet sniffer built on a supplied skeleton with a thread pool). **This repository is a rewrite**, not the submitted coursework. The original had problems that I found when reviewing it as a security tool:

| Original | Now |
|---|---|
| Queue never checked for "full": a flood overwrote unprocessed packets | Bounded queue. Live capture drops and **counts** packets when full; file replay blocks so nothing is lost |
| Headers parsed with no length checks; `strstr` on a non-NUL-terminated payload | Every read is checked against the captured length; Host header found with a bounded scan |
| Unique-IP check was a linear scan of an array under one global lock (O(n^2) overall) | Hash set |
| SYN-ACK replies counted as SYN attack packets | Only SYN without ACK counts |
| Substring match on the Host header (`www.google.co.uk.evil.net` matched) | Exact host match, case-insensitive, port stripped, headers only |
| Detached workers; the report printed while workers were still running, so queued packets were lost | Joinable workers; `queue_close` then `pool_join` drains everything before the report |
| Lazy array initialisation raced between workers | No lazy init; detector is built before any thread starts |
| Global counters and getters read without a lock | Detector struct with one mutex and a locked snapshot |
| `getopt_long` option table had no terminator (undefined behaviour) | Terminated |
| Manual testing only | Automated unit tests, sanitizer builds, pcap replay |

## Design decisions and limitations

- **Drop vs block.** On a live interface, blocking the capture thread just moves the loss into the kernel buffer where it is invisible, so the queue drops and reports the count (plus the kernel's own drop count from `pcap_stats`). For file replay, blocking is safe and gives deterministic results.
- **Single detector mutex.** Simple and correct; the critical sections are tiny. Sharding the counters would be the next step if profiling showed contention.
- **Scope.** IPv4 and TCP only. No TCP stream reassembly, so a `Host` header split across two segments is missed. IP fragments after the first are ignored. Blacklist matching is by exact hostname.
- **Snaplen.** Only the first 2048 bytes of each packet are kept, which is plenty for headers and the start of an HTTP request.

