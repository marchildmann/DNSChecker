#include "lookup_task.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct worker_job {
    lookup_task *task;
    lookup_report *report;   /* domain filled in by the starter */
    char extra_names[SCAN_EXTRA_NAMES_CAPACITY];
} worker_job;

/* ------------------------------------------------------------------------ */
/* The thread                                                               */
/* ------------------------------------------------------------------------ */

static void *lookup_worker(void *argument) {
    worker_job *job = argument;
    domain_scan_run(job->report, job->extra_names);

    pthread_mutex_lock(&job->task->lock);
    free(job->task->finished_report);   /* a report nobody picked up */
    job->task->finished_report = job->report;
    job->task->is_running = false;
    pthread_mutex_unlock(&job->task->lock);

    free(job);
    return NULL;
}

void lookup_task_init(lookup_task *task) {
    pthread_mutex_init(&task->lock, NULL);
    task->is_running = false;
    task->finished_report = NULL;
}

static worker_job *create_job(lookup_task *task, const char *domain, const char *extra_names) {
    worker_job *job = calloc(1, sizeof *job);
    lookup_report *report = calloc(1, sizeof *report);
    if (!job || !report) {
        free(job);
        free(report);
        return NULL;
    }
    snprintf(report->domain, sizeof report->domain, "%s", domain);
    snprintf(job->extra_names, sizeof job->extra_names, "%s", extra_names ? extra_names : "");
    job->task = task;
    job->report = report;
    return job;
}

static void set_running(lookup_task *task, bool is_running) {
    pthread_mutex_lock(&task->lock);
    task->is_running = is_running;
    pthread_mutex_unlock(&task->lock);
}

static bool start_worker_thread(worker_job *job) {
    pthread_t thread;
    if (pthread_create(&thread, NULL, lookup_worker, job) != 0) return false;
    pthread_detach(thread);
    return true;
}

bool lookup_task_start(lookup_task *task, const char *domain, const char *extra_names) {
    if (lookup_task_is_running(task)) return false;
    worker_job *job = create_job(task, domain, extra_names);
    if (!job) return false;

    set_running(task, true);   /* before the thread exists, so it cannot finish first */
    if (start_worker_thread(job)) return true;

    set_running(task, false);
    free(job->report);
    free(job);
    return false;
}

bool lookup_task_is_running(lookup_task *task) {
    pthread_mutex_lock(&task->lock);
    bool is_running = task->is_running;
    pthread_mutex_unlock(&task->lock);
    return is_running;
}

lookup_report *lookup_task_take_report(lookup_task *task) {
    pthread_mutex_lock(&task->lock);
    lookup_report *report = task->finished_report;
    task->finished_report = NULL;
    pthread_mutex_unlock(&task->lock);
    return report;
}
