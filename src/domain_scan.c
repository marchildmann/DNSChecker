#include "domain_scan.h"

#include <arpa/nameser.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

const char *const scan_common_dkim_selectors[] = {
    "google",                    /* Google Workspace */
    "selector1", "selector2",    /* Microsoft 365 */
    "k1",                        /* Mailchimp */
    "s1", "s2",                  /* SendGrid */
    "default",                   /* many hosting panels */
};
const int scan_common_dkim_selector_count =
    sizeof scan_common_dkim_selectors / sizeof scan_common_dkim_selectors[0];

static const char *const common_host_names[] = { "www" };

/* What is asked below the domain: hosts get the address and mail types,
 * service names (_dmarc, s1._domainkey) only carry TXT. */
static const int host_alias_types[] = { ns_t_cname };
static const int host_record_types[] = { ns_t_a, ns_t_aaaa, ns_t_mx, ns_t_txt };
static const int service_record_types[] = { ns_t_txt };

enum { MAX_SCAN_TARGETS = 64, SELECTOR_CAPACITY = 128 };

typedef struct scan_target {
    char name[DNS_DOMAIN_CAPACITY];
    bool is_dkim_key;            /* "<selector>._domainkey.<domain>" */
} scan_target;

typedef struct scan_plan {
    scan_target targets[MAX_SCAN_TARGETS];
    int count;
} scan_plan;

/* ------------------------------------------------------------------------ */
/* Plan: which names to ask for                                             */
/* ------------------------------------------------------------------------ */

static bool plan_contains(const scan_plan *plan, const char *name) {
    for (int i = 0; i < plan->count; i++)
        if (strcmp(plan->targets[i].name, name) == 0) return true;
    return false;
}

static bool is_dkim_key_name(const char *name) {
    return strstr(name, "._domainkey.") != NULL;
}

/* `relative_name` such as "www" or "s1._domainkey"; the domain itself is
 * scanned separately and never added. */
static void plan_add(scan_plan *plan, const char *domain, const char *relative_name) {
    char name[DNS_DOMAIN_CAPACITY];
    if (plan->count >= MAX_SCAN_TARGETS) return;
    if (!dns_qualify_name(relative_name, domain, name, sizeof name)) return;
    if (strcmp(name, domain) == 0 || plan_contains(plan, name)) return;

    scan_target *target = &plan->targets[plan->count++];
    snprintf(target->name, sizeof target->name, "%s", name);
    target->is_dkim_key = is_dkim_key_name(name);
}

/* Copies the next entry of a list separated by commas, semicolons or white
 * space into `out`. Returns false at the end. */
static bool next_list_entry(const char **cursor, char *out, size_t capacity) {
    static const char separators[] = ", ;\t\r\n";
    const char *at = *cursor + strspn(*cursor, separators);
    if (*at == '\0') return false;

    size_t length = strcspn(at, separators);
    *cursor = at + length;
    if (length >= capacity) length = capacity - 1;
    memcpy(out, at, length);
    out[length] = '\0';
    return true;
}

static void build_scan_plan(const char *domain, const char *extra_names, scan_plan *plan) {
    char entry[DNS_DOMAIN_CAPACITY], dkim_name[DNS_DOMAIN_CAPACITY];
    plan->count = 0;

    for (size_t i = 0; i < sizeof common_host_names / sizeof common_host_names[0]; i++)
        plan_add(plan, domain, common_host_names[i]);
    for (int i = 0; i < scan_common_dkim_selector_count; i++) {
        snprintf(dkim_name, sizeof dkim_name, "%s._domainkey", scan_common_dkim_selectors[i]);
        plan_add(plan, domain, dkim_name);
    }

    const char *cursor = extra_names ? extra_names : "";
    while (next_list_entry(&cursor, entry, sizeof entry)) plan_add(plan, domain, entry);
}

/* ------------------------------------------------------------------------ */
/* Queries                                                                  */
/* ------------------------------------------------------------------------ */

static const char *type_label(int type_code) {
    for (int i = 0; i < dns_record_type_count; i++)
        if (dns_record_types[i].code == type_code) return dns_record_types[i].label;
    return "?";
}

static void note_failed_query(lookup_report *report, const char *name, int type_code) {
    size_t used = strlen(report->failed_queries);
    snprintf(report->failed_queries + used, sizeof report->failed_queries - used, "%s%s (%s)", used ? ", " : "", name,
             type_label(type_code));
}

/* A type that fails is noted and the others still run. Returns
 * DNS_STATUS_NO_SUCH_DOMAIN as soon as the name turns out not to exist. */
static const dns_server *server_of(const lookup_report *report) {
    return report->asks_name_server_directly ? &report->name_server : NULL;
}

static dns_status query_types(lookup_report *report, const char *name, const int *type_codes, int type_count) {
    for (int i = 0; i < type_count; i++) {
        dns_status status = dns_query(server_of(report), name, type_codes[i], &report->records);
        if (status == DNS_STATUS_NO_SUCH_DOMAIN) return status;
        if (status == DNS_STATUS_FAILURE) note_failed_query(report, name, type_codes[i]);
    }
    return DNS_STATUS_OK;
}

static dns_status query_domain_itself(lookup_report *report) {
    int type_codes[16];
    for (int i = 0; i < dns_record_type_count; i++) type_codes[i] = dns_record_types[i].code;
    dns_status status = query_types(report, report->domain, type_codes, dns_record_type_count);
    if (status == DNS_STATUS_NO_SUCH_DOMAIN) return status;
    return report->records.count > 0 ? DNS_STATUS_OK : DNS_STATUS_NO_DATA;
}

static bool has_underscore_label(const char *name) {
    return name[0] == '_' || strstr(name, "._") != NULL;
}

static bool answer_has_alias(const dns_record_list *list, int first) {
    for (int i = first; i < list->count; i++)
        if (strcmp(list->records[i].type, "CNAME") == 0) return true;
    return false;
}

/* The zone's own name server answers an alias into another zone with the
 * CNAME alone; the system resolver follows it to the target's records. */
static void query_service_name(lookup_report *report, const char *name) {
    int records_before = report->records.count;
    query_types(report, name, service_record_types, 1);
    bool stops_at_alias = report->asks_name_server_directly && answer_has_alias(&report->records, records_before);
    if (stops_at_alias) dns_query(NULL, name, ns_t_txt, &report->records);
}

/* A name with a CNAME has no other records of its own: asking further would
 * only list the records of the alias target, which belong to someone else
 * (pm-bounces -> pm.mtasv.net). Service names are still followed, because a
 * DKIM key behind a CNAME (Microsoft 365) is only visible at the target. */
static void query_target(lookup_report *report, const scan_target *target) {
    if (has_underscore_label(target->name)) {
        query_service_name(report, target->name);
        return;
    }
    int records_before = report->records.count;
    if (query_types(report, target->name, host_alias_types, 1) == DNS_STATUS_NO_SUCH_DOMAIN) return;
    bool is_alias = report->records.count > records_before;
    if (is_alias) return;
    query_types(report, target->name, host_record_types, sizeof host_record_types / sizeof host_record_types[0]);
}

/* ------------------------------------------------------------------------ */
/* Mail authentication summary                                              */
/* ------------------------------------------------------------------------ */

static bool starts_with_ignoring_case(const char *text, const char *prefix) {
    for (; *prefix; text++, prefix++)
        if (tolower((unsigned char)*text) != tolower((unsigned char)*prefix)) return false;
    return true;
}

static const dns_record *find_text_record(const dns_record_list *list, const char *prefix) {
    for (int i = 0; i < list->count; i++) {
        const dns_record *record = &list->records[i];
        if (strcmp(record->type, "TXT") == 0 && starts_with_ignoring_case(record->value, prefix)) return record;
    }
    return NULL;
}

bool dkim_record_has_key(const char *record) {
    const char *tag = record;
    while (*tag) {
        while (*tag == ';' || isspace((unsigned char)*tag)) tag++;
        size_t tag_length = strcspn(tag, ";");
        if (tag_length >= 2 && tag[0] == 'p' && tag[1] == '=') {
            const char *key = tag + 2;
            while (key < tag + tag_length && isspace((unsigned char)*key)) key++;
            return key < tag + tag_length;
        }
        tag += tag_length;
    }
    return false;
}

static bool answer_holds_dkim_key(const dns_record_list *list, int first) {
    for (int i = first; i < list->count; i++) {
        const dns_record *record = &list->records[i];
        if (strcmp(record->type, "TXT") == 0 && dkim_record_has_key(record->value)) return true;
    }
    return false;
}

static void note_dkim_selector(mail_security_summary *mail, const char *key_name) {
    char selector[SELECTOR_CAPACITY];
    size_t length = strstr(key_name, "._domainkey.") - key_name;
    snprintf(selector, sizeof selector, "%.*s", (int)length, key_name);

    size_t used = strlen(mail->dkim_selectors);
    snprintf(mail->dkim_selectors + used, sizeof mail->dkim_selectors - used, "%s%s",
             mail->dkim_selector_count == 0 ? "" : ", ", selector);
    mail->dkim_selector_count++;
}

/* Runs before the names below the domain are asked, so every record in the
 * list belongs to the domain itself (or the target of its CNAME). */
static void summarize_domain_records(const dns_record_list *records, mail_security_summary *mail) {
    mail->mail_exchanger_count = 0;
    for (int i = 0; i < records->count; i++)
        if (strcmp(records->records[i].type, "MX") == 0) mail->mail_exchanger_count++;

    const dns_record *spf = find_text_record(records, "v=spf1");
    mail->has_spf = spf != NULL;
    if (spf) snprintf(mail->spf_record, sizeof mail->spf_record, "%s", spf->value);
}

/* The DMARC record is shown on the summary card and the DMARC page, not in
 * the table, so it is asked into a list of its own. That list is too large
 * for a worker thread's stack. */
static void look_up_dmarc(const lookup_report *report, mail_security_summary *mail) {
    char dmarc_host[DNS_DOMAIN_CAPACITY + 8];
    dns_record_list *answer = calloc(1, sizeof *answer);
    if (!answer) return;

    snprintf(dmarc_host, sizeof dmarc_host, "_dmarc.%s", report->domain);
    dns_query(server_of(report), dmarc_host, ns_t_txt, answer);
    const dns_record *dmarc = find_text_record(answer, "v=DMARC1");
    mail->has_dmarc = dmarc != NULL;
    if (dmarc) snprintf(mail->dmarc_record, sizeof mail->dmarc_record, "%s", dmarc->value);
    free(answer);
}

/* ------------------------------------------------------------------------ */
/* Names below the domain                                                   */
/* ------------------------------------------------------------------------ */

static void scan_names_below_domain(lookup_report *report, const char *extra_names) {
    scan_plan *plan = calloc(1, sizeof *plan);
    if (!plan) return;
    build_scan_plan(report->domain, extra_names, plan);

    for (int i = 0; i < plan->count; i++) {
        int first_new_record = report->records.count;
        query_target(report, &plan->targets[i]);
        if (plan->targets[i].is_dkim_key && answer_holds_dkim_key(&report->records, first_new_record))
            note_dkim_selector(&report->mail, plan->targets[i].name);
    }
    free(plan);
}

/* ------------------------------------------------------------------------ */
/* DKIM selectors with a date in their name                                 */
/* ------------------------------------------------------------------------ */

/* Hetzner (konsoleH, managed servers) names each key "default" plus the
 * year and month it was made, e.g. default2502. Keys older than this are
 * not looked for. */
enum { DATED_SELECTOR_FIRST_YEAR = 2018 };

/* "_domainkey.<domain>" exists (NOERROR, no data) as soon as any selector
 * is published below it, whatever its name; NXDOMAIN means there is none. */
static bool has_names_below_domainkey(lookup_report *report) {
    char domainkey_name[DNS_DOMAIN_CAPACITY + 16];
    snprintf(domainkey_name, sizeof domainkey_name, "_domainkey.%s", report->domain);
    int records_before = report->records.count;
    dns_status status = dns_query(server_of(report), domainkey_name, ns_t_txt, &report->records);
    report->records.count = records_before;   /* only whether it exists matters */
    return status == DNS_STATUS_OK || status == DNS_STATUS_NO_DATA;
}

/* Tries one selector; keeps its record and notes it when it holds a key. */
static bool try_dkim_selector(lookup_report *report, const char *selector) {
    char key_name[DNS_DOMAIN_CAPACITY + 64];
    snprintf(key_name, sizeof key_name, "%s._domainkey.%s", selector, report->domain);
    int records_before = report->records.count;
    dns_query(server_of(report), key_name, ns_t_txt, &report->records);
    if (answer_holds_dkim_key(&report->records, records_before)) {
        note_dkim_selector(&report->mail, key_name);
        return true;
    }
    report->records.count = records_before;
    return false;
}

/* Goes back month by month from today, so the newest key is the one found. */
static void search_dated_selectors(lookup_report *report) {
    char selector[16];
    time_t now = time(NULL);
    struct tm today;
    localtime_r(&now, &today);

    for (int year = today.tm_year + 1900; year >= DATED_SELECTOR_FIRST_YEAR; year--) {
        int last_month = year == today.tm_year + 1900 ? today.tm_mon + 1 : 12;
        for (int month = last_month; month >= 1; month--) {
            snprintf(selector, sizeof selector, "default%02d%02d", year % 100, month);
            if (try_dkim_selector(report, selector)) return;
        }
    }
}

static void search_unlisted_dkim_selectors(lookup_report *report) {
    if (report->mail.dkim_selector_count > 0) return;
    if (!has_names_below_domainkey(report)) return;
    search_dated_selectors(report);
    report->mail.has_unknown_dkim_selectors = report->mail.dkim_selector_count == 0;
}

/* ------------------------------------------------------------------------ */
/* The zone's own name server                                               */
/* ------------------------------------------------------------------------ */

static bool resolve_ipv4(const char *host_name, char *address, size_t capacity) {
    dns_record_list *answer = calloc(1, sizeof *answer);
    if (!answer) return false;
    dns_query(NULL, host_name, ns_t_a, answer);
    bool was_found = false;
    for (int i = 0; i < answer->count && !was_found; i++) {
        if (strcmp(answer->records[i].type, "A") != 0) continue;
        snprintf(address, capacity, "%s", answer->records[i].value);
        was_found = true;
    }
    free(answer);
    return was_found;
}

/* A server is usable when it answers for the domain at all; one that times
 * out or refuses is skipped. */
static bool server_answers_for(const dns_server *server, const char *domain) {
    dns_record_list *answer = calloc(1, sizeof *answer);
    if (!answer) return false;
    dns_status status = dns_query(server, domain, ns_t_soa, answer);
    free(answer);
    return status != DNS_STATUS_FAILURE;
}

static bool pick_answering_server(const dns_record_list *name_servers, const char *domain, dns_server *server) {
    for (int i = 0; i < name_servers->count; i++) {
        if (strcmp(name_servers->records[i].type, "NS") != 0) continue;
        snprintf(server->host_name, sizeof server->host_name, "%s", name_servers->records[i].value);
        if (!resolve_ipv4(server->host_name, server->address, sizeof server->address)) continue;
        if (server_answers_for(server, domain)) return true;
    }
    return false;
}

/* The zone's name servers are found through the system resolver, walking
 * up from the name typed: lp.example.com has none of its own, its zone
 * example.com has. Top-level domains are not asked. */
static bool find_zone_name_server(const char *domain, dns_server *server) {
    dns_record_list *name_servers = calloc(1, sizeof *name_servers);
    if (!name_servers) return false;
    bool was_found = false;
    for (const char *zone = domain; zone && strchr(zone, '.') && !was_found; zone = strchr(zone, '.') + 1) {
        name_servers->count = 0;
        dns_query(NULL, zone, ns_t_ns, name_servers);
        was_found = pick_answering_server(name_servers, domain, server);
        if (name_servers->count > 0) break;   /* the zone is found, whether a server answered or not */
    }
    free(name_servers);
    return was_found;
}

/* ------------------------------------------------------------------------ */
/* Scan                                                                     */
/* ------------------------------------------------------------------------ */

void domain_scan_run(lookup_report *report, const char *extra_names) {
    report->asks_name_server_directly = find_zone_name_server(report->domain, &report->name_server);
    report->status = query_domain_itself(report);
    if (report->status == DNS_STATUS_NO_SUCH_DOMAIN) return;

    summarize_domain_records(&report->records, &report->mail);
    look_up_dmarc(report, &report->mail);
    scan_names_below_domain(report, extra_names);
    search_unlisted_dkim_selectors(report);
}
