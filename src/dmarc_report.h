/* DMARC aggregate reports (RFC 7489, appendix C): the XML files receivers
 * such as Google and Microsoft send to the rua address. Each report lists,
 * per sending IP, how many messages arrived and whether SPF and DKIM passed.
 * A library holds every report loaded and merges their rows per sender. */
#ifndef DMARC_REPORT_H
#define DMARC_REPORT_H

#include <stdbool.h>
#include <stddef.h>

enum {
    REPORT_NAME_CAPACITY = 256,
    REPORT_SHORT_CAPACITY = 64,
    REPORT_ERROR_CAPACITY = 256,
};

/* One sender as a receiver saw it: a row of a report, or after merging,
 * the same sender across several reports. */
typedef struct dmarc_report_row {
    char source_ip[REPORT_SHORT_CAPACITY];
    long message_count;
    char disposition[REPORT_SHORT_CAPACITY];   /* what the receiver did: none, quarantine, reject */
    bool dkim_passed;                          /* DKIM passed and matches the From domain */
    bool spf_passed;                           /* SPF passed and matches the From domain */
    char header_from[REPORT_NAME_CAPACITY];
    char dkim_domain[REPORT_NAME_CAPACITY];    /* the first DKIM signature checked */
    char dkim_selector[REPORT_SHORT_CAPACITY];
    char spf_domain[REPORT_NAME_CAPACITY];     /* the envelope sender's domain SPF checked */
} dmarc_report_row;

typedef struct dmarc_report {
    char reporter[REPORT_NAME_CAPACITY];       /* org_name, e.g. "google.com" */
    char report_id[REPORT_NAME_CAPACITY];
    long long begin_time, end_time;            /* seconds since 1970 */
    char policy_domain[REPORT_NAME_CAPACITY];
    char published_policy[REPORT_SHORT_CAPACITY];
    dmarc_report_row *rows;
    int row_count;
} dmarc_report;

typedef struct dmarc_report_library {
    dmarc_report *reports;
    int report_count;
    dmarc_report_row *senders;                 /* every report's rows merged, failing senders first */
    int sender_count;
    long total_messages;
    long passing_messages;
    long long first_time, last_time;           /* the span all reports cover */
} dmarc_report_library;

typedef enum report_add_result {
    REPORT_ADDED = 0,
    REPORT_ALREADY_LOADED,                     /* same reporter and report id as one loaded before */
    REPORT_UNREADABLE,
} report_add_result;

/* DMARC passes when either SPF or DKIM passed in alignment. */
bool dmarc_row_passes(const dmarc_report_row *row);

report_add_result dmarc_library_add_file(dmarc_report_library *library, const char *path, char *error, size_t error_capacity);
report_add_result dmarc_library_add_xml(dmarc_report_library *library, const char *xml, size_t length, char *error,
                                        size_t error_capacity);
void dmarc_library_clear(dmarc_report_library *library);

#endif
