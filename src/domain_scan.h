/* Everything one click on "Abfragen" looks up, asked of the zone's own name
 * server: every record type of the domain itself, well-known names below it
 * (www, common DKIM selectors), the names the user adds, and the mail
 * authentication summary drawn from those answers. Blocks on the network;
 * lookup_task.h runs it on a thread. */
#ifndef DOMAIN_SCAN_H
#define DOMAIN_SCAN_H

#include "dns_lookup.h"

enum {
    SCAN_PROBLEM_CAPACITY = 512,
    SCAN_EXTRA_NAMES_CAPACITY = 1024,
    SCAN_SELECTOR_LIST_CAPACITY = 512,
};

/* DKIM selectors of common mail services, tried on every scan. When none
 * of them and none of the user's names has a key, but names exist below
 * _domainkey, the scan also tries Hetzner's dated ones (default2502). */
extern const char *const scan_common_dkim_selectors[];
extern const int scan_common_dkim_selector_count;

typedef struct mail_security_summary {
    int mail_exchanger_count;
    bool has_spf;
    char spf_record[DNS_VALUE_CAPACITY];
    bool has_dmarc;
    char dmarc_record[DNS_VALUE_CAPACITY];
    int dkim_selector_count;
    char dkim_selectors[SCAN_SELECTOR_LIST_CAPACITY];   /* "google, s1", the selectors with a key */
    bool has_unknown_dkim_selectors;   /* selectors exist below _domainkey, but none of the names tried */
} mail_security_summary;

typedef struct lookup_report {
    char domain[DNS_DOMAIN_CAPACITY];
    /* Queries go straight to one of the zone's name servers, so the report
     * shows what the zone holds now, not what a cache remembers. Without a
     * server that answers, they fall back to the system resolver. */
    bool asks_name_server_directly;
    dns_server name_server;
    dns_record_list records;                  /* the domain's own records first, then the other names */
    char problem[SCAN_PROBLEM_CAPACITY];      /* empty when every query was answered */
    mail_security_summary mail;
} lookup_report;

/* True when a DKIM record publishes a key: a non-empty p= tag, usually
 * after "v=DKIM1; k=rsa; ". An empty p= means the key was revoked. */
bool dkim_record_has_key(const char *record);

/* Fills `report`, whose `domain` is set and normalized. `extra_names` is the
 * user's list of names, separated by commas or spaces, either relative
 * ("lp", "s1._domainkey") or complete ("lp.example.com"). */
void domain_scan_run(lookup_report *report, const char *extra_names);

#endif
