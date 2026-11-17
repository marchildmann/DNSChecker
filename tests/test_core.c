/* Tests for the parts that need neither a window nor the network:
 * domain names, DMARC records, DMARC aggregate reports and the UI texts. */
#include "dmarc.h"
#include "dmarc_report.h"
#include "dns_lookup.h"
#include "dns_wire.h"
#include "domain_scan.h"
#include "ui_text.h"

#include <stdio.h>
#include <string.h>

static int failure_count = 0;

static void expect_text(const char *what, const char *actual, const char *expected) {
    if (strcmp(actual, expected) == 0) return;
    printf("FAIL %s\n  expected: %s\n  actual:   %s\n", what, expected, actual);
    failure_count++;
}

static void expect_true(const char *what, bool condition) {
    if (condition) return;
    printf("FAIL %s\n", what);
    failure_count++;
}

static void expect_normalized(const char *input, const char *expected) {
    char domain[DNS_DOMAIN_CAPACITY];
    bool is_valid = dns_normalize_domain(input, domain, sizeof domain);
    expect_true(input, is_valid);
    if (is_valid) expect_text(input, domain, expected);
}

static void expect_rejected(const char *input) {
    char domain[DNS_DOMAIN_CAPACITY];
    expect_true(input, !dns_normalize_domain(input, domain, sizeof domain));
}

static void test_domain_normalization(void) {
    expect_normalized("example.com", "example.com");
    expect_normalized("  Example.COM.  ", "example.com");
    expect_normalized("https://www.example.com/path?q=1", "www.example.com");
    expect_normalized("example.com:443", "example.com");
    expect_normalized("_dmarc.example.com", "_dmarc.example.com");
    expect_rejected("");
    expect_rejected("   ");
    expect_rejected("exa mple.com");
    expect_rejected("example..com");
    expect_rejected("bücher.de");   /* IDN needs punycode first */
}

static void expect_qualified(const char *entry, const char *expected) {
    char name[DNS_DOMAIN_CAPACITY];
    bool is_valid = dns_qualify_name(entry, "example.com", name, sizeof name);
    expect_true(entry, is_valid);
    if (is_valid) expect_text(entry, name, expected);
}

static void expect_relative(const char *name, const char *expected) {
    char relative[DNS_DOMAIN_CAPACITY];
    dns_relative_name(name, "example.com", relative, sizeof relative);
    expect_text(name, relative, expected);
}

static void test_names_below_domain(void) {
    char name[DNS_DOMAIN_CAPACITY];
    expect_qualified("www", "www.example.com");
    expect_qualified("S1._domainkey", "s1._domainkey.example.com");
    expect_qualified("lp.example.com", "lp.example.com");
    expect_qualified("@", "example.com");
    expect_qualified("example.com", "example.com");
    expect_qualified("badexample.com", "badexample.com.example.com");   /* not below the domain: relative */
    expect_true("invalid entry", !dns_qualify_name("a b", "example.com", name, sizeof name));

    expect_relative("example.com", "@");
    expect_relative("www.example.com", "www");
    expect_relative("google._domainkey.example.com", "google._domainkey");
    expect_relative("github.com", "github.com");
    expect_relative("badexample.com", "badexample.com");
}

static void test_dkim_keys(void) {
    expect_true("key", dkim_record_has_key("v=DKIM1; k=rsa; p=MIIBIjANBgkq"));
    expect_true("key without spaces", dkim_record_has_key("k=rsa;p=MIGfMA0GCSq"));
    expect_true("revoked key", !dkim_record_has_key("v=DKIM1; p="));
    expect_true("revoked key with space", !dkim_record_has_key("v=DKIM1; p= ;"));
    expect_true("no p tag", !dkim_record_has_key("v=spf1 -all"));
    expect_true("p inside another tag", !dkim_record_has_key("v=DKIM1; s=email:p=x"));
}

static size_t read_fixture(const char *file_name, unsigned char *out, size_t capacity) {
    char path[1024];
    snprintf(path, sizeof path, "%s/%s", FIXTURE_DIR, file_name);
    FILE *file = fopen(path, "rb");
    if (!file) return 0;
    size_t length = fread(out, 1, capacity, file);
    fclose(file);
    return length;
}

static bool list_has(const dns_record_list *list, const char *type, const char *name, const char *value) {
    for (int i = 0; i < list->count; i++) {
        const dns_record *record = &list->records[i];
        if (!strcmp(record->type, type) && !strcmp(record->name, name) && !strcmp(record->value, value)) return true;
    }
    return false;
}

static void test_wire_query(void) {
    static const unsigned char expected[] = {
        0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
        3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
        0x01, 0x01, 0, 1,
    };
    unsigned char query[DNS_WIRE_MESSAGE_CAPACITY];
    size_t length = dns_wire_build_query(0x1234, "www.example.com", RECORD_TYPE_CAA, query, sizeof query);
    expect_true("query length", length == sizeof expected);
    expect_true("query bytes", length == sizeof expected && memcmp(query, expected, length) == 0);
    expect_true("empty label refused", dns_wire_build_query(1, "a..b", RECORD_TYPE_CAA, query, sizeof query) == 0);
}

/* A real response of github.com's name server to a CAA query (id 0x1234),
 * with its names compressed. */
static void test_wire_response(void) {
    static dns_record_list list;
    unsigned char message[DNS_WIRE_MESSAGE_CAPACITY];
    size_t length = read_fixture("caa_github_com.bin", message, sizeof message);
    expect_true("fixture read", length > 12);

    list.count = 0;
    expect_true("response read", dns_wire_read_response(message, length, 0x1234, &list) == DNS_STATUS_OK);
    expect_true("seven CAA records", list.count == 7);
    expect_true("issue letsencrypt", list_has(&list, "CAA", "github.com", "0 issue \"letsencrypt.org\""));
    expect_true("issuewild digicert", list_has(&list, "CAA", "github.com", "0 issuewild \"digicert.com\""));

    list.count = 0;
    expect_true("another query's id", dns_wire_read_response(message, length, 0x4321, &list) == DNS_STATUS_FAILURE);
    expect_true("cut short", dns_wire_read_response(message, length - 5, 0x1234, &list) == DNS_STATUS_FAILURE);

    unsigned char looping[] = { 0x12, 0x34, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 12 };
    expect_true("pointer loop", dns_wire_read_response(looping, sizeof looping, 0x1234, &list) == DNS_STATUS_FAILURE);
    unsigned char missing[] = { 0x12, 0x34, 0x81, 0x83, 0, 0, 0, 0, 0, 0, 0, 0 };
    expect_true("NXDOMAIN", dns_wire_read_response(missing, sizeof missing, 0x1234, &list) == DNS_STATUS_NO_SUCH_DOMAIN);
}

static void expect_record(const char *what, dmarc_settings settings, const char *expected) {
    char record[DMARC_RECORD_CAPACITY];
    expect_true(what, dmarc_build_record(&settings, record, sizeof record));
    expect_text(what, record, expected);
}

static void test_dmarc_records(void) {
    expect_record("defaults are omitted", (dmarc_settings){ .percentage = 100 }, "v=DMARC1; p=none");
    expect_record("every tag",
                  (dmarc_settings){
                      .policy = DMARC_POLICY_REJECT,
                      .has_subdomain_policy = true,
                      .subdomain_policy = DMARC_POLICY_QUARANTINE,
                      .percentage = 50,
                      .aggregate_report_addresses = "a@example.com, mailto:b@example.com",
                      .failure_report_addresses = "f@example.com",
                      .failure_reporting = DMARC_FAILURE_WHEN_ANY_FAILS,
                      .dkim_alignment = DMARC_ALIGNMENT_STRICT,
                      .spf_alignment = DMARC_ALIGNMENT_STRICT,
                  },
                  "v=DMARC1; p=reject; sp=quarantine; pct=50; rua=mailto:a@example.com,mailto:b@example.com; "
                  "ruf=mailto:f@example.com; fo=1; adkim=s; aspf=s");
    expect_record("fo needs ruf",
                  (dmarc_settings){ .percentage = 100, .failure_reporting = DMARC_FAILURE_WHEN_DKIM_FAILS },
                  "v=DMARC1; p=none");

    char tiny[8];
    expect_true("too small buffer fails", !dmarc_build_record(&(dmarc_settings){ .percentage = 100 }, tiny, sizeof tiny));
}

static void expect_round_trip(const char *record) {
    dmarc_settings settings;
    char rebuilt[DMARC_RECORD_CAPACITY];
    expect_true(record, dmarc_parse_record(record, &settings));
    expect_true(record, dmarc_build_record(&settings, rebuilt, sizeof rebuilt));
    expect_text(record, rebuilt, record);
}

static void test_dmarc_parsing(void) {
    dmarc_settings settings;
    expect_round_trip("v=DMARC1; p=quarantine");
    expect_round_trip("v=DMARC1; p=reject; sp=none; pct=25; rua=mailto:a@example.com,mailto:b@example.org; "
                      "ruf=mailto:f@example.com; fo=d; adkim=s; aspf=s");

    expect_true("loose spelling", dmarc_parse_record(" v = DMARC1 ;P=Reject;rua=mailto:x@example.com ;ri=3600", &settings));
    expect_true("loose spelling policy", settings.policy == DMARC_POLICY_REJECT);
    expect_text("addresses shown without mailto", settings.aggregate_report_addresses, "x@example.com");

    expect_true("defaults spelled out", dmarc_records_are_equivalent("v=DMARC1;p=none;sp=none;pct=50;adkim=r;aspf=r;",
                                                                     "v=DMARC1; p=none; sp=none; pct=50"));
    expect_true("different policy", !dmarc_records_are_equivalent("v=DMARC1; p=none", "v=DMARC1; p=reject"));
    expect_true("not dmarc", !dmarc_parse_record("v=spf1 -all", &settings));
    expect_true("version must come first", !dmarc_parse_record("p=reject; v=DMARC1", &settings));
}

static void test_dmarc_addresses(void) {
    char foreign[DNS_DOMAIN_CAPACITY];
    expect_true("empty list is fine", dmarc_address_list_is_valid(""));
    expect_true("two addresses", dmarc_address_list_is_valid("a@example.com, mailto:b@example.org"));
    expect_true("missing at sign", !dmarc_address_list_is_valid("example.com"));
    expect_true("missing domain dot", !dmarc_address_list_is_valid("a@localhost"));

    expect_true("same domain", !dmarc_find_foreign_report_domain("example.com", "a@example.com", foreign, sizeof foreign));
    expect_true("parent domain", !dmarc_find_foreign_report_domain("mail.example.com", "a@example.com", foreign, sizeof foreign));
    expect_true("lookalike is foreign", dmarc_find_foreign_report_domain("example.com", "a@badexample.com", foreign, sizeof foreign));
    expect_text("foreign domain", foreign, "badexample.com");
}

static report_add_result add_fixture(dmarc_report_library *library, const char *file_name) {
    char path[1024];
    report_error error;
    snprintf(path, sizeof path, "%s/%s", FIXTURE_DIR, file_name);
    return dmarc_library_add_file(library, path, &error);
}

static void test_dmarc_reports(void) {
    dmarc_report_library library = { 0 };
    expect_true("zip from Google", add_fixture(&library, "report_google.zip") == REPORT_ADDED);
    expect_true("gzip from Microsoft", add_fixture(&library, "report_microsoft.xml.gz") == REPORT_ADDED);
    expect_true("same report as plain xml", add_fixture(&library, "report_google.xml") == REPORT_ALREADY_LOADED);

    expect_true("two reports", library.report_count == 2);
    expect_true("all messages", library.total_messages == 40 + 3 + 10 + 3);
    expect_true("passing messages", library.passing_messages == 40 + 10);
    expect_true("rows merged per sender", library.sender_count == 2);
    expect_text("failing sender first", library.senders[0].source_ip, "198.51.100.7");
    expect_true("failing sender summed", library.senders[0].message_count == 6);
    expect_text("failing sender disposition", library.senders[0].disposition, "quarantine");
    expect_text("dkim selector", library.senders[1].dkim_selector, "google");

    report_error error;
    const char not_a_report[] = "<html><body>hi</body></html>";
    expect_true("not a report", dmarc_library_add_xml(&library, not_a_report, sizeof not_a_report - 1, &error) ==
                                    REPORT_UNREADABLE && error == REPORT_ERROR_NOT_A_REPORT);
    expect_true("missing file", add_fixture(&library, "missing.xml") == REPORT_UNREADABLE);
    dmarc_library_clear(&library);
    expect_true("cleared", library.report_count == 0 && library.sender_count == 0);
}

/* The conversions of a printf format in order, e.g. "%d (%s)" gives "ds";
 * "%%" is a literal percent sign and does not count. */
static void format_conversions(const char *format, char *out, size_t capacity) {
    size_t used = 0;
    for (const char *at = format; *at && used + 1 < capacity; at++) {
        if (*at != '%') continue;
        at++;
        if (*at == '%') continue;
        while (*at && !strchr("diouxXeEfFgGcsp", *at)) at++;   /* flags, width, precision, length */
        if (*at) out[used++] = *at;
    }
    out[used] = '\0';
}

/* Both structs hold nothing but `const char *`, so they can be walked as arrays. */
static void test_ui_texts(void) {
    enum { STRING_COUNT = sizeof(ui_strings) / sizeof(const char *), FORMAT_COUNT = sizeof(ui_formats) / sizeof(const char *) };
    const ui_text *german = ui_text_for(UI_LANGUAGE_GERMAN), *english = ui_text_for(UI_LANGUAGE_ENGLISH);
    const char *const *german_strings = (const char *const *)&german->strings;
    const char *const *english_strings = (const char *const *)&english->strings;
    const char *const *german_formats = (const char *const *)&german->formats;
    const char *const *english_formats = (const char *const *)&english->formats;
    char label[64], german_conversions[16], english_conversions[16];

    for (int i = 0; i < STRING_COUNT; i++) {
        snprintf(label, sizeof label, "string %d present in both languages", i);
        expect_true(label, german_strings[i] && english_strings[i] && german_strings[i][0] && english_strings[i][0]);
    }
    for (int i = 0; i < FORMAT_COUNT; i++) {
        snprintf(label, sizeof label, "format %d present in both languages", i);
        expect_true(label, german_formats[i] && english_formats[i]);
        if (!german_formats[i] || !english_formats[i]) continue;
        format_conversions(german_formats[i], german_conversions, sizeof german_conversions);
        format_conversions(english_formats[i], english_conversions, sizeof english_conversions);
        snprintf(label, sizeof label, "format %d takes the same arguments", i);
        expect_text(label, english_conversions, german_conversions);
    }
    expect_true("every report error worded", ui_report_error_message(english, REPORT_ERROR_OUT_OF_MEMORY)[0] != '\0');
    expect_text("plural", ui_plural(1, "one", "other"), "one");
    expect_text("plural of zero", ui_plural(0, "one", "other"), "other");

    char day[16];
    ui_format_day(english, 1763337599, day, sizeof day);
    expect_true("US date has slashes", strchr(day, '/') != NULL);
    ui_format_day(german, 1763337599, day, sizeof day);
    expect_true("German date has dots", strchr(day, '.') != NULL);
}

int main(void) {
    test_domain_normalization();
    test_names_below_domain();
    test_dkim_keys();
    test_wire_query();
    test_wire_response();
    test_dmarc_records();
    test_dmarc_parsing();
    test_dmarc_addresses();
    test_dmarc_reports();
    test_ui_texts();
    if (failure_count == 0) printf("all tests passed\n");
    return failure_count == 0 ? 0 : 1;
}
