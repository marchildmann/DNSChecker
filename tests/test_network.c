/* A real lookup of github.com, which publishes every kind of record the app
 * shows. It needs the network, so it is not part of ctest; CI runs it on
 * each system to show that system's DNS code reads every record type. */
#include "domain_scan.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failure_count = 0;

static void expect_true(const char *what, bool condition) {
    printf("%s %s\n", condition ? "ok  " : "FAIL", what);
    if (!condition) failure_count++;
}

static const dns_record *find_record(const lookup_report *report, const char *type, const char *value_part) {
    for (int i = 0; i < report->records.count; i++) {
        const dns_record *record = &report->records.records[i];
        if (strcmp(record->type, type) == 0 && strstr(record->value, value_part)) return record;
    }
    return NULL;
}

int main(void) {
    lookup_report *report = calloc(1, sizeof *report);
    if (!report) return 1;
    snprintf(report->domain, sizeof report->domain, "github.com");
    domain_scan_run(report, "www");

    printf("asked %s; failed queries: [%s]\n", report->asks_name_server_directly ? report->name_server.host_name
                                                                                   : "the system resolver",
           report->failed_queries);
    expect_true("the zone's own name server answered", report->asks_name_server_directly);
    expect_true("the domain exists", report->status == DNS_STATUS_OK);
    expect_true("A record", find_record(report, "A", ".") != NULL);
    expect_true("MX record with preference and host", find_record(report, "MX", " ") != NULL);
    expect_true("NS record", find_record(report, "NS", ".") != NULL);
    expect_true("SOA record with its timers", find_record(report, "SOA", "serial ") != NULL);
    expect_true("CAA record decoded", find_record(report, "CAA", "issue \"") != NULL);
    expect_true("CNAME for www", find_record(report, "CNAME", "github.com") != NULL);
    expect_true("SPF found", report->mail.has_spf);
    expect_true("DMARC found", report->mail.has_dmarc && strncmp(report->mail.dmarc_record, "v=DMARC1", 8) == 0);
    expect_true("a DKIM key found", report->mail.dkim_selector_count > 0);

    free(report);
    printf(failure_count == 0 ? "network test passed\n" : "network test FAILED\n");
    return failure_count == 0 ? 0 : 1;
}
