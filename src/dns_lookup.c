#include "dns_lookup.h"

#include "dns_lookup_internal.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

const dns_record_type dns_record_types[] = {
    { "A", RECORD_TYPE_A },
    { "AAAA", RECORD_TYPE_AAAA },
    { "CNAME", RECORD_TYPE_CNAME },
    { "MX", RECORD_TYPE_MX },
    { "NS", RECORD_TYPE_NS },
    { "TXT", RECORD_TYPE_TXT },
    { "SOA", RECORD_TYPE_SOA },
    { "CAA", RECORD_TYPE_CAA },
};
const int dns_record_type_count = sizeof dns_record_types / sizeof dns_record_types[0];

enum { MAX_HOST_NAME_LENGTH = 253 };

/* ------------------------------------------------------------------------ */
/* Domain input                                                             */
/* ------------------------------------------------------------------------ */

static bool is_host_name_character(char c) {
    return isalnum((unsigned char)c) || c == '-' || c == '.' || c == '_';
}

static const char *skip_url_scheme(const char *text) {
    const char *scheme_end = strstr(text, "://");
    return scheme_end ? scheme_end + 3 : text;
}

static bool is_valid_host_name(const char *name) {
    size_t length = strlen(name);
    if (length == 0 || length > MAX_HOST_NAME_LENGTH) return false;
    if (name[0] == '.' || strstr(name, "..")) return false;
    for (size_t i = 0; i < length; i++)
        if (!is_host_name_character(name[i])) return false;
    return true;
}

bool dns_normalize_domain(const char *input, char *out, size_t capacity) {
    while (isspace((unsigned char)*input)) input++;
    const char *start = skip_url_scheme(input);

    /* the host ends at the first path, port or query; a space inside it
     * stays and makes the name invalid */
    size_t length = strcspn(start, "/:?#");
    while (length > 0 && (isspace((unsigned char)start[length - 1]) || start[length - 1] == '.')) length--;
    if (length == 0 || length >= capacity) return false;

    for (size_t i = 0; i < length; i++) out[i] = (char)tolower((unsigned char)start[i]);
    out[length] = '\0';
    return is_valid_host_name(out);
}

/* True when `name` is a name below `domain`, such as www.example.com. */
static bool is_below_domain(const char *name, const char *domain) {
    size_t name_length = strlen(name), domain_length = strlen(domain);
    if (name_length <= domain_length + 1) return false;
    const char *tail = name + name_length - domain_length;
    return tail[-1] == '.' && strcmp(tail, domain) == 0;
}

bool dns_qualify_name(const char *entry, const char *domain, char *out, size_t capacity) {
    char name[DNS_DOMAIN_CAPACITY];
    if (strcmp(entry, "@") == 0) {
        snprintf(out, capacity, "%s", domain);
        return true;
    }
    if (!dns_normalize_domain(entry, name, sizeof name)) return false;

    bool is_complete = strcmp(name, domain) == 0 || is_below_domain(name, domain);
    int written = is_complete ? snprintf(out, capacity, "%s", name) : snprintf(out, capacity, "%s.%s", name, domain);
    return written > 0 && (size_t)written < capacity && is_valid_host_name(out);
}

void dns_relative_name(const char *name, const char *domain, char *out, size_t capacity) {
    if (strcmp(name, domain) == 0) {
        snprintf(out, capacity, "@");
        return;
    }
    if (!is_below_domain(name, domain)) {
        snprintf(out, capacity, "%s", name);
        return;
    }
    size_t relative_length = strlen(name) - strlen(domain) - 1;
    snprintf(out, capacity, "%.*s", (int)relative_length, name);
}

/* ------------------------------------------------------------------------ */
/* Records as text, shared by the query files                               */
/* ------------------------------------------------------------------------ */

void dns_append_printable(char *out, size_t capacity, size_t *used, const unsigned char *bytes, size_t length) {
    for (size_t i = 0; i < length && *used + 1 < capacity; i++) {
        unsigned char c = bytes[i];
        out[(*used)++] = (c >= 0x20 && c != 0x7f) ? (char)c : '?';
    }
    out[*used] = '\0';
}

void dns_format_mail_exchanger(unsigned preference, const char *exchanger, char *out, size_t capacity) {
    snprintf(out, capacity, "%u %s", preference, exchanger);
}

void dns_format_start_of_authority(const char *primary_server, const char *responsible_mailbox,
                                   const unsigned long timers[5], char *out, size_t capacity) {
    snprintf(out, capacity, "%s %s serial %lu, refresh %lu, retry %lu, expire %lu, minimum %lu", primary_server,
             responsible_mailbox, timers[0], timers[1], timers[2], timers[3], timers[4]);
}

bool dns_format_certification_authority(const unsigned char *data, size_t length, char *out, size_t capacity) {
    if (length < 2) return false;
    unsigned flags = data[0];
    size_t tag_length = data[1];
    if (2 + tag_length > length) return false;

    int prefix_length = snprintf(out, capacity, "%u %.*s \"", flags, (int)tag_length, (const char *)data + 2);
    if (prefix_length < 0 || (size_t)prefix_length >= capacity) return false;
    size_t used = (size_t)prefix_length;
    dns_append_printable(out, capacity, &used, data + 2 + tag_length, length - 2 - tag_length);
    if (used + 1 < capacity) {
        out[used++] = '"';
        out[used] = '\0';
    }
    return true;
}

void dns_format_undecoded(size_t length, char *out, size_t capacity) {
    snprintf(out, capacity, "(%zu bytes, not decoded)", length);
}

static void describe_type(int type_code, char *out, size_t capacity) {
    for (int i = 0; i < dns_record_type_count; i++) {
        if (dns_record_types[i].code != type_code) continue;
        snprintf(out, capacity, "%s", dns_record_types[i].label);
        return;
    }
    snprintf(out, capacity, "TYPE%d", type_code);
}

static bool is_same_record(const dns_record *first, const dns_record *second) {
    return strcmp(first->type, second->type) == 0 && strcasecmp(first->name, second->name) == 0 &&
           strcmp(first->value, second->value) == 0;
}

static bool list_contains(const dns_record_list *list, const dns_record *candidate) {
    for (int i = 0; i < list->count; i++)
        if (is_same_record(&list->records[i], candidate)) return true;
    return false;
}

void dns_record_list_add(dns_record_list *list, int type_code, const char *name, unsigned long ttl_seconds,
                         const char *value) {
    if (list->count >= DNS_MAX_RECORDS) return;
    dns_record *record = &list->records[list->count];
    describe_type(type_code, record->type, sizeof record->type);
    snprintf(record->name, sizeof record->name, "%s", name);
    record->ttl_seconds = ttl_seconds;
    snprintf(record->value, sizeof record->value, "%s", value);
    if (!list_contains(list, record)) list->count++;
}
