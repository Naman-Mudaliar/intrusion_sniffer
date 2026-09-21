#include "check.h"
#include "ipset.h"

int main(void) {
  ipset *s = ipset_new();
  CHECK(s != NULL);
  CHECK(ipset_count(s) == 0);

  CHECK(ipset_add(s, 42) == 1);
  CHECK(ipset_add(s, 42) == 0);
  CHECK(ipset_count(s) == 1);

  /* 0.0.0.0 is a legitimate key and must not be confused with "empty slot" */
  CHECK(ipset_add(s, 0) == 1);
  CHECK(ipset_add(s, 0) == 0);
  CHECK(ipset_count(s) == 2);

  /* 100k inserts force several resizes */
  for (uint32_t i = 1000; i < 101000; i++) {
    CHECK(ipset_add(s, i) == 1);
  }
  CHECK(ipset_count(s) == 100002);

  /* re-inserting everything changes nothing */
  for (uint32_t i = 1000; i < 101000; i++) {
    CHECK(ipset_add(s, i) == 0);
  }
  CHECK(ipset_add(s, 42) == 0);
  CHECK(ipset_add(s, 0) == 0);
  CHECK(ipset_count(s) == 100002);

  /* highest key and colliding-looking keys */
  CHECK(ipset_add(s, 0xFFFFFFFFu) == 1);
  CHECK(ipset_add(s, 0xFFFFFFFFu) == 0);

  ipset_free(s);
  return TEST_RESULT();
}
