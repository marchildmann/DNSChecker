/* Building DMARC records (RFC 7489) from a few choices, reading published
 * records back into those choices, and checking the report addresses that
 * go into them. No UI and no network here. */
#ifndef DMARC_H
#define DMARC_H

#include <stdbool.h>
#include <stddef.h>

enum { DMARC_RECORD_CAPACITY = 2048, DMARC_ADDRESS_LIST_CAPACITY = 512 };

typedef enum dmarc_policy {
    DMARC_POLICY_NONE = 0,       /* only monitor */
    DMARC_POLICY_QUARANTINE,     /* deliver failing mail as spam */
    DMARC_POLICY_REJECT,         /* refuse failing mail */
} dmarc_policy;

typedef enum dmarc_alignment {
    DMARC_ALIGNMENT_RELAXED = 0, /* the organizational domains must match */
    DMARC_ALIGNMENT_STRICT,      /* the exact domains must match */
} dmarc_alignment;

/* When a receiver sends a failure report (tag fo). */
typedef enum dmarc_failure_reporting {
    DMARC_FAILURE_WHEN_ALL_FAIL = 0,   /* fo=0, the default */
    DMARC_FAILURE_WHEN_ANY_FAILS,      /* fo=1 */
    DMARC_FAILURE_WHEN_DKIM_FAILS,     /* fo=d */
    DMARC_FAILURE_WHEN_SPF_FAILS,      /* fo=s */
} dmarc_failure_reporting;

typedef struct dmarc_settings {
    dmarc_policy policy;
    bool has_subdomain_policy;         /* without one, subdomains follow `policy` */
    dmarc_policy subdomain_policy;
    int percentage;                    /* share of failing mail the policy applies to, 0..100 */
    /* comma separated mail addresses, with or without "mailto:" */
    char aggregate_report_addresses[DMARC_ADDRESS_LIST_CAPACITY];   /* rua: daily summaries */
    char failure_report_addresses[DMARC_ADDRESS_LIST_CAPACITY];     /* ruf: reports per failed message */
    dmarc_failure_reporting failure_reporting;
    dmarc_alignment dkim_alignment;
    dmarc_alignment spf_alignment;
} dmarc_settings;

/* Writes the TXT value, e.g. "v=DMARC1; p=quarantine; rua=mailto:a@example.com".
 * Tags left at their defaults are omitted. Returns false when it does not fit. */
bool dmarc_build_record(const dmarc_settings *settings, char *out, size_t capacity);

/* Reads a published record such as "v=DMARC1; p=reject; rua=mailto:a@x.de"
 * into `settings`; tags it leaves out get their defaults, unknown tags are
 * ignored. Returns false when the text is not a DMARC record. */
bool dmarc_parse_record(const char *record, dmarc_settings *settings);

/* True when two records mean the same, written differently: tags in
 * another order, defaults spelled out ("adkim=r"), other spacing. False
 * when either is not a DMARC record. */
bool dmarc_records_are_equivalent(const char *first, const char *second);

/* The name the record is published under: "_dmarc.<domain>". */
void dmarc_record_host(const char *domain, char *out, size_t capacity);

/* True when every address in the comma separated list looks like a mail
 * address. An empty list is fine. */
bool dmarc_address_list_is_valid(const char *addresses);

/* True when one of the addresses is outside `domain`: the receiving domain
 * then has to publish "<domain>._report._dmarc.<its domain>" to accept the
 * reports. The first such domain is written to `foreign_domain`. */
bool dmarc_find_foreign_report_domain(const char *domain, const char *addresses, char *foreign_domain, size_t capacity);

const char *dmarc_policy_keyword(dmarc_policy policy);

#endif
