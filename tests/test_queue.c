#include <pthread.h>
#include <string.h>
#include <unistd.h>

#include "check.h"
#include "queue.h"

static void test_full_and_order(void) {
  queue *q = queue_new(4);
  CHECK(q != NULL);
  for (uint8_t i = 0; i < 4; i++) {
    CHECK(queue_push(q, &i, 1, 0) == 0);
  }
  uint8_t extra = 99;
  CHECK(queue_push(q, &extra, 1, 0) == -1); /* full: dropped, not overwritten */
  CHECK(queue_dropped(q) == 1);

  job j;
  for (uint8_t i = 0; i < 4; i++) {
    CHECK(queue_pop(q, &j) == 1);
    CHECK(j.caplen == 1 && j.data[0] == i); /* FIFO, and the first 4 survived intact */
  }
  /* wrap-around: refill after draining */
  for (uint8_t i = 10; i < 14; i++) {
    CHECK(queue_push(q, &i, 1, 0) == 0);
  }
  CHECK(queue_pop(q, &j) == 1 && j.data[0] == 10);

  queue_close(q);
  CHECK(queue_pop(q, &j) == 1 && j.data[0] == 11); /* closed queue still drains */
  CHECK(queue_pop(q, &j) == 1 && j.data[0] == 12);
  CHECK(queue_pop(q, &j) == 1 && j.data[0] == 13);
  CHECK(queue_pop(q, &j) == 0);                    /* closed and empty */
  CHECK(queue_push(q, &extra, 1, 0) == -1);           /* no pushes after close */
  queue_free(q);
}

static void test_oversized_packet_clamped(void) {
  queue *q = queue_new(2);
  static uint8_t big[SNAPLEN * 2];
  memset(big, 7, sizeof big);
  CHECK(queue_push(q, big, sizeof big, 0) == 0);
  job j;
  CHECK(queue_pop(q, &j) == 1);
  CHECK(j.caplen == SNAPLEN);
  queue_free(q);
}

static void *blocked_popper(void *arg) {
  job j;
  static int result;
  result = queue_pop((queue *)arg, &j);
  return &result;
}

static void test_close_wakes_waiter(void) {
  queue *q = queue_new(4);
  pthread_t t;
  pthread_create(&t, NULL, blocked_popper, q);
  usleep(50000); /* let it block in cond_wait (if close wins the race the result is the same) */
  queue_close(q);
  void *ret;
  pthread_join(t, &ret);
  CHECK(*(int *)ret == 0);
  queue_free(q);
}

#define TOTAL 200000
#define CONSUMERS 4

typedef struct { queue *q; uint64_t consumed; } consumer_ctx;

static void *consumer(void *arg) {
  consumer_ctx *c = arg;
  job j;
  while (queue_pop(c->q, &j)) {
    c->consumed++;
  }
  return NULL;
}

/* accepted + dropped must equal what was offered, and everything accepted
 * must be consumed (nothing lost in shutdown). Run under TSan for races. */
static void test_concurrent(void) {
  queue *q = queue_new(64);
  pthread_t th[CONSUMERS];
  consumer_ctx ctx[CONSUMERS];
  for (int i = 0; i < CONSUMERS; i++) {
    ctx[i].q = q;
    ctx[i].consumed = 0;
    pthread_create(&th[i], NULL, consumer, &ctx[i]);
  }
  uint64_t accepted = 0;
  for (uint32_t i = 0; i < TOTAL; i++) {
    uint8_t b[4];
    memcpy(b, &i, 4);
    if (queue_push(q, b, 4, 0) == 0) accepted++;
  }
  queue_close(q);
  uint64_t consumed = 0;
  for (int i = 0; i < CONSUMERS; i++) {
    pthread_join(th[i], NULL);
    consumed += ctx[i].consumed;
  }
  CHECK(accepted + queue_dropped(q) == TOTAL);
  CHECK(consumed == accepted);
  queue_free(q);
}

typedef struct { queue *q; uint64_t seen; uint32_t last; int in_order; } slow_ctx;

static void *slow_consumer(void *arg) {
  slow_ctx *c = arg;
  job j;
  while (queue_pop(c->q, &j)) {
    uint32_t v;
    memcpy(&v, j.data, 4);
    if (c->seen > 0 && v != c->last + 1) c->in_order = 0;
    c->last = v;
    c->seen++;
  }
  return NULL;
}

/* Blocking mode (used for file replay): a capacity-1 queue must still deliver
 * every packet, in order, with zero drops. */
static void test_blocking_push(void) {
  queue *q = queue_new(1);
  slow_ctx c = {.q = q, .seen = 0, .last = 0, .in_order = 1};
  pthread_t t;
  pthread_create(&t, NULL, slow_consumer, &c);
  for (uint32_t i = 0; i < 5000; i++) {
    CHECK(queue_push(q, (const uint8_t *)&i, 4, 1) == 0);
  }
  queue_close(q);
  pthread_join(t, NULL);
  CHECK(c.seen == 5000);
  CHECK(c.in_order);
  CHECK(queue_dropped(q) == 0);
  queue_free(q);
}

/* A producer blocked on a full queue must be released by close, not hang. */
static void *blocked_pusher(void *arg) {
  static int r;
  uint8_t b = 1;
  r = queue_push((queue *)arg, &b, 1, 1);
  return &r;
}

static void test_close_wakes_blocked_pusher(void) {
  queue *q = queue_new(1);
  uint8_t b = 0;
  CHECK(queue_push(q, &b, 1, 0) == 0); /* now full */
  pthread_t t;
  pthread_create(&t, NULL, blocked_pusher, q);
  usleep(50000);
  queue_close(q);
  void *ret;
  pthread_join(t, &ret);
  CHECK(*(int *)ret == -1);
  queue_free(q);
}

int main(void) {
  CHECK(queue_new(0) == NULL);
  test_blocking_push();
  test_close_wakes_blocked_pusher();
  test_full_and_order();
  test_oversized_packet_clamped();
  test_close_wakes_waiter();
  test_concurrent();
  return TEST_RESULT();
}
