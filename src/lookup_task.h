/* Runs DNS lookups on a worker thread, so the window stays responsive while
 * the resolver waits. The worker never touches the UI: it hands a finished
 * report over, and the frame function picks it up with lookup_task_take_report. */
#ifndef LOOKUP_TASK_H
#define LOOKUP_TASK_H

#include "domain_scan.h"

#include <pthread.h>
#include <stdbool.h>

typedef struct lookup_task {
    pthread_mutex_t lock;
    bool is_running;
    lookup_report *finished_report;          /* set by the worker, taken by the UI */
} lookup_task;

void lookup_task_init(lookup_task *task);

/* Starts a domain_scan_run unless a lookup is running. `domain` must
 * already be normalized; `extra_names` is copied. */
bool lookup_task_start(lookup_task *task, const char *domain, const char *extra_names);

bool lookup_task_is_running(lookup_task *task);

/* The report of a finished lookup, once; the caller frees it. NULL otherwise. */
lookup_report *lookup_task_take_report(lookup_task *task);

#endif
