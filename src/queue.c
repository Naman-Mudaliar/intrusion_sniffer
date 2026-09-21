#include "queue.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct queue {
  job *slots;
  size_t cap;
  size_t head;  /* next slot to pop */
  size_t tail;  /* next slot to fill */
  size_t count; /* count (not head==tail) distinguishes full from empty */
  int closed;
  uint64_t dropped;
  pthread_mutex_t lock;
  pthread_cond_t not_empty;
  pthread_cond_t not_full;
};

queue *queue_new(size_t capacity) {
  if (capacity == 0) {
    return NULL;
  }
  queue *q = calloc(1, sizeof *q);
  if (q == NULL) {
    return NULL;
  }
  q->slots = malloc(capacity * sizeof *q->slots);
  if (q->slots == NULL) {
    free(q);
    return NULL;
  }
  q->cap = capacity;
  pthread_mutex_init(&q->lock, NULL);
  pthread_cond_init(&q->not_empty, NULL);
  pthread_cond_init(&q->not_full, NULL);
  return q;
}

int queue_push(queue *q, const uint8_t *pkt, size_t caplen, int block) {
  if (caplen > SNAPLEN) {
    caplen = SNAPLEN;
  }
  pthread_mutex_lock(&q->lock);
  while (block && q->count == q->cap && !q->closed) {
    pthread_cond_wait(&q->not_full, &q->lock);
  }
  if (q->closed || q->count == q->cap) {
    q->dropped++;
    pthread_mutex_unlock(&q->lock);
    return -1;
  }
  job *slot = &q->slots[q->tail];
  slot->caplen = (uint32_t)caplen;
  memcpy(slot->data, pkt, caplen);
  q->tail = (q->tail + 1) % q->cap;
  q->count++;
  pthread_cond_signal(&q->not_empty);
  pthread_mutex_unlock(&q->lock);
  return 0;
}

int queue_pop(queue *q, job *out) {
  pthread_mutex_lock(&q->lock);
  while (q->count == 0 && !q->closed) {
    pthread_cond_wait(&q->not_empty, &q->lock);
  }
  if (q->count == 0) { /* closed and drained */
    pthread_mutex_unlock(&q->lock);
    return 0;
  }
  const job *slot = &q->slots[q->head];
  out->caplen = slot->caplen;
  memcpy(out->data, slot->data, slot->caplen);
  q->head = (q->head + 1) % q->cap;
  q->count--;
  pthread_cond_signal(&q->not_full);
  pthread_mutex_unlock(&q->lock);
  return 1;
}

void queue_close(queue *q) {
  pthread_mutex_lock(&q->lock);
  q->closed = 1;
  pthread_cond_broadcast(&q->not_empty);
  pthread_cond_broadcast(&q->not_full);
  pthread_mutex_unlock(&q->lock);
}

uint64_t queue_dropped(queue *q) {
  pthread_mutex_lock(&q->lock);
  uint64_t d = q->dropped;
  pthread_mutex_unlock(&q->lock);
  return d;
}

void queue_free(queue *q) {
  if (q == NULL) {
    return;
  }
  pthread_mutex_destroy(&q->lock);
  pthread_cond_destroy(&q->not_empty);
  pthread_cond_destroy(&q->not_full);
  free(q->slots);
  free(q);
}
