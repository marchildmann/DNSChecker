/* The state the window keeps between frames, shared by both pages. */
#ifndef APP_STATE_H
#define APP_STATE_H

#include "dmarc.h"
#include "dmarc_report.h"
#include "lookup_task.h"

#include <cui/cui.h>

/* The DMARC page's choices as the controls hold them (indices of the
 * segmented controls and selects); dmarc_settings_from_form maps them. */
typedef struct dmarc_form {
    int policy_index;               /* dmarc_policy */
    int subdomain_policy_index;     /* 0: like the domain, then dmarc_policy + 1 */
    double percentage;
    char aggregate_addresses[DMARC_ADDRESS_LIST_CAPACITY];
    char failure_addresses[DMARC_ADDRESS_LIST_CAPACITY];
    int failure_reporting_index;    /* dmarc_failure_reporting */
    int dkim_alignment_index;       /* dmarc_alignment */
    int spf_alignment_index;        /* dmarc_alignment */
} dmarc_form;

typedef struct app_state {
    int active_page;
    char domain_input[DNS_DOMAIN_CAPACITY];
    char extra_names_input[SCAN_EXTRA_NAMES_CAPACITY];   /* "lp, 7eleven, xyz._domainkey" */
    bool was_lookup_attempted;      /* show a domain error only after the first try */
    lookup_task lookup;
    lookup_report *report;          /* the newest finished lookup, owned here; NULL before the first */
    int record_filter_index;        /* 0: every type, then dns_record_types index + 1 */
    dmarc_form dmarc;
    bool is_dmarc_form_from_published;   /* the form holds the record the last lookup found */
    dmarc_report_library report_library;
    char report_load_message[512];       /* what the last drop or file dialog loaded */
    bool has_report_load_problem;
} app_state;

/* The domain field as a host name, or "" when it is not one. */
void app_current_domain(const app_state *app, char *out, size_t capacity);

void dmarc_form_reset(dmarc_form *form);
/* Fills the form from the published record, or resets it when there is
 * none. Returns true when a record was loaded. */
bool dmarc_form_load_published(dmarc_form *form, const mail_security_summary *mail);

void records_page(cui_ctx *ui, app_state *app);
void dmarc_page(cui_ctx *ui, app_state *app);
void reports_page(cui_ctx *ui, app_state *app);

#endif
