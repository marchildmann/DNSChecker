#include "dmarc.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

enum { ADDRESS_CAPACITY = 256 };

static const char MAILTO_PREFIX[] = "mailto:";

const char *dmarc_policy_keyword(dmarc_policy policy) {
    switch (policy) {
    case DMARC_POLICY_NONE: return "none";
    case DMARC_POLICY_QUARANTINE: return "quarantine";
    case DMARC_POLICY_REJECT: return "reject";
    }
    return "none";
}

static const char *failure_reporting_keyword(dmarc_failure_reporting reporting) {
    switch (reporting) {
    case DMARC_FAILURE_WHEN_ALL_FAIL: return "0";
    case DMARC_FAILURE_WHEN_ANY_FAILS: return "1";
    case DMARC_FAILURE_WHEN_DKIM_FAILS: return "d";
    case DMARC_FAILURE_WHEN_SPF_FAILS: return "s";
    }
    return "0";
}

void dmarc_record_host(const char *domain, char *out, size_t capacity) {
    snprintf(out, capacity, "_dmarc.%s", domain[0] ? domain : "example.com");
}

/* ------------------------------------------------------------------------ */
/* Address lists                                                            */
/* ------------------------------------------------------------------------ */

/* Copies the next entry of a comma separated list into `out`, without the
 * spaces around it and without a "mailto:" prefix. Returns false at the end. */
static bool next_address(const char **cursor, char *out, size_t capacity) {
    const char *at = *cursor;
    while (*at == ',' || isspace((unsigned char)*at)) at++;
    if (*at == '\0') return false;

    size_t length = strcspn(at, ",");
    *cursor = at + length;
    while (length > 0 && isspace((unsigned char)at[length - 1])) length--;
    if (length >= strlen(MAILTO_PREFIX) && strncasecmp(at, MAILTO_PREFIX, strlen(MAILTO_PREFIX)) == 0) {
        at += strlen(MAILTO_PREFIX);
        length -= strlen(MAILTO_PREFIX);
    }
    if (length >= capacity) length = capacity - 1;
    memcpy(out, at, length);
    out[length] = '\0';
    return true;
}

static bool looks_like_mail_address(const char *address) {
    const char *at_sign = strchr(address, '@');
    if (!at_sign || at_sign == address || strchr(at_sign + 1, '@')) return false;
    const char *dot = strchr(at_sign + 1, '.');
    bool domain_has_dot = dot && dot > at_sign + 1 && dot[1] != '\0';
    bool has_space = strpbrk(address, " \t") != NULL;
    return domain_has_dot && !has_space;
}

bool dmarc_address_list_is_valid(const char *addresses) {
    char address[ADDRESS_CAPACITY];
    const char *cursor = addresses;
    while (next_address(&cursor, address, sizeof address))
        if (!looks_like_mail_address(address)) return false;
    return true;
}

/* True when `name` is `parent` or one of its subdomains. */
static bool is_within_domain(const char *name, const char *parent) {
    size_t name_length = strlen(name), parent_length = strlen(parent);
    if (name_length < parent_length) return false;
    const char *tail = name + name_length - parent_length;
    bool tail_matches = strcasecmp(tail, parent) == 0;
    return tail_matches && (tail == name || tail[-1] == '.');
}

/* Without the public suffix list the organizational domain is not known, so
 * two domains count as one organization when one lies within the other. */
static bool belongs_to_same_organization(const char *first, const char *second) {
    return is_within_domain(first, second) || is_within_domain(second, first);
}

bool dmarc_find_foreign_report_domain(const char *domain, const char *addresses, char *foreign_domain, size_t capacity) {
    char address[ADDRESS_CAPACITY];
    const char *cursor = addresses;
    while (next_address(&cursor, address, sizeof address)) {
        const char *at_sign = strchr(address, '@');
        if (!at_sign || belongs_to_same_organization(at_sign + 1, domain)) continue;
        snprintf(foreign_domain, capacity, "%s", at_sign + 1);
        return true;
    }
    return false;
}

/* ------------------------------------------------------------------------ */
/* Record                                                                   */
/* ------------------------------------------------------------------------ */

typedef struct record_writer {
    char *out;
    size_t capacity;
    size_t used;
    bool overflowed;
} record_writer;

static void writer_append(record_writer *writer, const char *format, ...) {
    if (writer->overflowed) return;
    va_list arguments;
    va_start(arguments, format);
    int written = vsnprintf(writer->out + writer->used, writer->capacity - writer->used, format, arguments);
    va_end(arguments);
    if (written < 0 || (size_t)written >= writer->capacity - writer->used) {
        writer->overflowed = true;
        return;
    }
    writer->used += (size_t)written;
}

/* "a@x.de, mailto:b@y.de" becomes "mailto:a@x.de,mailto:b@y.de". */
static void append_address_tag(record_writer *writer, const char *tag, const char *addresses) {
    char address[ADDRESS_CAPACITY];
    const char *cursor = addresses;
    const char *separator = "";
    while (next_address(&cursor, address, sizeof address)) {
        if (separator[0] == '\0') writer_append(writer, "; %s=", tag);
        writer_append(writer, "%s%s%s", separator, MAILTO_PREFIX, address);
        separator = ",";
    }
}

static bool has_addresses(const char *addresses) {
    char address[ADDRESS_CAPACITY];
    const char *cursor = addresses;
    return next_address(&cursor, address, sizeof address);
}

bool dmarc_build_record(const dmarc_settings *settings, char *out, size_t capacity) {
    record_writer writer = { out, capacity, 0, capacity == 0 };
    if (capacity > 0) out[0] = '\0';

    writer_append(&writer, "v=DMARC1; p=%s", dmarc_policy_keyword(settings->policy));
    if (settings->has_subdomain_policy)
        writer_append(&writer, "; sp=%s", dmarc_policy_keyword(settings->subdomain_policy));
    if (settings->percentage < 100)
        writer_append(&writer, "; pct=%d", settings->percentage < 0 ? 0 : settings->percentage);
    append_address_tag(&writer, "rua", settings->aggregate_report_addresses);
    append_address_tag(&writer, "ruf", settings->failure_report_addresses);

    /* fo only matters to receivers that send failure reports, so it goes with ruf */
    bool wants_failure_reports = has_addresses(settings->failure_report_addresses);
    if (wants_failure_reports && settings->failure_reporting != DMARC_FAILURE_WHEN_ALL_FAIL)
        writer_append(&writer, "; fo=%s", failure_reporting_keyword(settings->failure_reporting));
    if (settings->dkim_alignment == DMARC_ALIGNMENT_STRICT) writer_append(&writer, "; adkim=s");
    if (settings->spf_alignment == DMARC_ALIGNMENT_STRICT) writer_append(&writer, "; aspf=s");

    return !writer.overflowed;
}

/* ------------------------------------------------------------------------ */
/* Reading a published record                                               */
/* ------------------------------------------------------------------------ */

typedef struct dmarc_tag {
    char name[16];
    char value[DMARC_ADDRESS_LIST_CAPACITY];
} dmarc_tag;

static void copy_trimmed(const char *start, size_t length, char *out, size_t capacity) {
    while (length > 0 && isspace((unsigned char)*start)) start++, length--;
    while (length > 0 && isspace((unsigned char)start[length - 1])) length--;
    snprintf(out, capacity, "%.*s", (int)length, start);
}

/* Reads the next "name=value" of a record whose tags are separated by ';'.
 * Returns false at the end. A part without '=' gets an empty value. */
static bool next_tag(const char **cursor, dmarc_tag *tag) {
    const char *at = *cursor;
    while (*at == ';' || isspace((unsigned char)*at)) at++;
    if (*at == '\0') return false;

    size_t length = strcspn(at, ";");
    *cursor = at + length;
    const char *equals = memchr(at, '=', length);
    size_t name_length = equals ? (size_t)(equals - at) : length;
    copy_trimmed(at, name_length, tag->name, sizeof tag->name);
    if (equals) copy_trimmed(equals + 1, length - name_length - 1, tag->value, sizeof tag->value);
    else tag->value[0] = '\0';
    return true;
}

static bool parse_policy(const char *value, dmarc_policy *policy) {
    for (dmarc_policy candidate = DMARC_POLICY_NONE; candidate <= DMARC_POLICY_REJECT; candidate++) {
        if (strcasecmp(value, dmarc_policy_keyword(candidate)) != 0) continue;
        *policy = candidate;
        return true;
    }
    return false;
}

/* "mailto:a@x.de,mailto:b@y.de" becomes "a@x.de, b@y.de", the way the form shows it. */
static void copy_addresses_for_form(const char *value, char *out, size_t capacity) {
    char address[ADDRESS_CAPACITY];
    const char *cursor = value;
    size_t used = 0;
    out[0] = '\0';
    while (next_address(&cursor, address, sizeof address) && used < capacity) {
        int written = snprintf(out + used, capacity - used, "%s%s", used ? ", " : "", address);
        if (written < 0) return;
        used += (size_t)written;
    }
}

/* fo may list several options ("0:d"); the form holds one, so the first wins. */
static dmarc_failure_reporting parse_failure_reporting(const char *value) {
    switch (tolower((unsigned char)value[0])) {
    case '1': return DMARC_FAILURE_WHEN_ANY_FAILS;
    case 'd': return DMARC_FAILURE_WHEN_DKIM_FAILS;
    case 's': return DMARC_FAILURE_WHEN_SPF_FAILS;
    default: return DMARC_FAILURE_WHEN_ALL_FAIL;
    }
}

static dmarc_alignment parse_alignment(const char *value) {
    return tolower((unsigned char)value[0]) == 's' ? DMARC_ALIGNMENT_STRICT : DMARC_ALIGNMENT_RELAXED;
}

static void apply_tag(const dmarc_tag *tag, dmarc_settings *settings) {
    const char *name = tag->name, *value = tag->value;
    if (strcasecmp(name, "p") == 0) parse_policy(value, &settings->policy);
    else if (strcasecmp(name, "sp") == 0) settings->has_subdomain_policy = parse_policy(value, &settings->subdomain_policy);
    else if (strcasecmp(name, "pct") == 0) settings->percentage = atoi(value);
    else if (strcasecmp(name, "rua") == 0)
        copy_addresses_for_form(value, settings->aggregate_report_addresses, sizeof settings->aggregate_report_addresses);
    else if (strcasecmp(name, "ruf") == 0)
        copy_addresses_for_form(value, settings->failure_report_addresses, sizeof settings->failure_report_addresses);
    else if (strcasecmp(name, "fo") == 0) settings->failure_reporting = parse_failure_reporting(value);
    else if (strcasecmp(name, "adkim") == 0) settings->dkim_alignment = parse_alignment(value);
    else if (strcasecmp(name, "aspf") == 0) settings->spf_alignment = parse_alignment(value);
}

bool dmarc_parse_record(const char *record, dmarc_settings *settings) {
    dmarc_tag tag;
    const char *cursor = record;
    *settings = (dmarc_settings){ .percentage = 100 };

    bool starts_with_version = next_tag(&cursor, &tag) && strcasecmp(tag.name, "v") == 0 &&
                               strcasecmp(tag.value, "DMARC1") == 0;
    if (!starts_with_version) return false;
    while (next_tag(&cursor, &tag)) apply_tag(&tag, settings);
    if (settings->percentage < 0 || settings->percentage > 100) settings->percentage = 100;
    return true;
}

/* Both are rebuilt the way dmarc_build_record writes them, then compared. */
bool dmarc_records_are_equivalent(const char *first, const char *second) {
    dmarc_settings first_settings, second_settings;
    char first_canonical[DMARC_RECORD_CAPACITY], second_canonical[DMARC_RECORD_CAPACITY];
    if (!dmarc_parse_record(first, &first_settings) || !dmarc_parse_record(second, &second_settings)) return false;
    if (!dmarc_build_record(&first_settings, first_canonical, sizeof first_canonical)) return false;
    if (!dmarc_build_record(&second_settings, second_canonical, sizeof second_canonical)) return false;
    return strcmp(first_canonical, second_canonical) == 0;
}
