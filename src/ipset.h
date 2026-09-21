#ifndef IPSET_H
#define IPSET_H

#include <stddef.h>
#include <stdint.h>

/*
 * Set of IPv4 addresses (open addressing, linear probing, power-of-two
 * capacity, grows at 70% load). NOT thread-safe: the caller must serialise
 * access (the detector holds its mutex around every call).
 */
typedef struct ipset ipset;

ipset *ipset_new(void);                    /* NULL on allocation failure */
int ipset_add(ipset *s, uint32_t ip);      /* 1 = newly added, 0 = already present, -1 = out of memory */
size_t ipset_count(const ipset *s);
void ipset_free(ipset *s);

#endif
