#ifndef CHECK_H
#define CHECK_H

#include <stdio.h>

/* Minimal test helper. CHECK is for the main thread only (the counter is not atomic). */
static int check_failures = 0;

#define CHECK(cond)                                                        \
  do {                                                                     \
    if (!(cond)) {                                                         \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
      check_failures++;                                                    \
    }                                                                      \
  } while (0)

#define TEST_RESULT() (check_failures ? (fprintf(stderr, "%d check(s) failed\n", check_failures), 1) : 0)

#endif
