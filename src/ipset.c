#include "ipset.h"

#include <stdlib.h>

#define IPSET_INITIAL_CAP 1024

struct ipset {
  uint32_t *keys;
  uint8_t *used; /* separate occupancy flags so that 0.0.0.0 is a valid key */
  size_t cap;    /* always a power of two */
  size_t count;
};

/* 32-bit integer mixer (multiply/xorshift) so sequential IPs spread out. */
static uint32_t mix(uint32_t x) {
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
}

static int alloc_tables(ipset *s, size_t cap) {
  s->keys = malloc(cap * sizeof *s->keys);
  s->used = calloc(cap, sizeof *s->used);
  if (s->keys == NULL || s->used == NULL) {
    free(s->keys);
    free(s->used);
    s->keys = NULL;
    s->used = NULL;
    return -1;
  }
  s->cap = cap;
  s->count = 0;
  return 0;
}

/* Inserts without growth checks. Returns 1 if inserted, 0 if present. */
static int insert_raw(uint32_t *keys, uint8_t *used, size_t cap, size_t *count,
                      uint32_t ip) {
  size_t mask = cap - 1;
  size_t i = mix(ip) & mask;
  while (used[i]) {
    if (keys[i] == ip) {
      return 0;
    }
    i = (i + 1) & mask;
  }
  used[i] = 1;
  keys[i] = ip;
  (*count)++;
  return 1;
}

static int grow(ipset *s) {
  size_t new_cap = s->cap * 2;
  if (new_cap < s->cap) {
    return -1;
  }
  uint32_t *nk = malloc(new_cap * sizeof *nk);
  uint8_t *nu = calloc(new_cap, sizeof *nu);
  if (nk == NULL || nu == NULL) {
    free(nk);
    free(nu);
    return -1;
  }
  size_t new_count = 0;
  for (size_t i = 0; i < s->cap; i++) {
    if (s->used[i]) {
      insert_raw(nk, nu, new_cap, &new_count, s->keys[i]);
    }
  }
  free(s->keys);
  free(s->used);
  s->keys = nk;
  s->used = nu;
  s->cap = new_cap;
  s->count = new_count;
  return 0;
}

ipset *ipset_new(void) {
  ipset *s = malloc(sizeof *s);
  if (s == NULL) {
    return NULL;
  }
  if (alloc_tables(s, IPSET_INITIAL_CAP) != 0) {
    free(s);
    return NULL;
  }
  return s;
}

int ipset_add(ipset *s, uint32_t ip) {
  if ((s->count + 1) * 10 > s->cap * 7) {
    if (grow(s) != 0) {
      return -1;
    }
  }
  return insert_raw(s->keys, s->used, s->cap, &s->count, ip);
}

size_t ipset_count(const ipset *s) { return s->count; }

void ipset_free(ipset *s) {
  if (s == NULL) {
    return;
  }
  free(s->keys);
  free(s->used);
  free(s);
}
