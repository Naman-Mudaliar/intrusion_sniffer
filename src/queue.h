#ifndef QUEUE_H
#define QUEUE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Bounded multi-producer / multi-consumer queue of captured packets.
 *
 * Policy when full depends on the caller:
 *   - live capture (block = 0): queue_push() never blocks. It drops the packet,
 *     counts it and returns -1. Blocking the capture thread would just move the
 *     loss into the kernel's capture buffer where nobody can see it; a counted
 *     drop is at least reported in the final output.
 *   - replaying a file (block = 1): queue_push() waits for space, so nothing is
 *     lost and the report is deterministic. (A file cannot overrun a kernel buffer.)
 *
 * Shutdown: queue_close() wakes every waiting consumer. queue_pop() keeps
 * returning jobs until the queue is empty and only then returns 0, so
 * everything accepted before the close is processed.
 */

#define SNAPLEN 2048 /* max bytes stored per packet; also the pcap snaplen */

typedef struct {
  uint32_t caplen;
  uint8_t data[SNAPLEN];
} job;

typedef struct queue queue;

queue *queue_new(size_t capacity);          /* NULL on failure or capacity == 0 */
int queue_push(queue *q, const uint8_t *pkt, size_t caplen, int block); /* 0 = queued, -1 = dropped */
int queue_pop(queue *q, job *out);          /* 1 = got a job, 0 = closed and drained */
void queue_close(queue *q);
uint64_t queue_dropped(queue *q);
void queue_free(queue *q);                  /* call only after all users have finished */

#endif
