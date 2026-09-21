#ifndef POOL_H
#define POOL_H

#include "detect.h"
#include "queue.h"

/* Fixed pool of joinable worker threads. Each worker loops:
 * pop packet -> parse -> detector_handle -> print any blacklist event. */
typedef struct pool pool;

/* NULL on failure (nothing is left running). */
pool *pool_start(queue *q, detector *d, int nworkers, int verbose);

/* Blocks until every worker has exited. Call queue_close() first: workers
 * only exit once the queue is closed AND drained. */
void pool_join(pool *p);

#endif
