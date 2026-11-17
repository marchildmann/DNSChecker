#include "dns_lookup.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* RFC 8659; older resolver headers (macOS) have no ns_t_caa */
enum { RECORD_TYPE_CAA = 257 };

const dns_record_type dns_record_types[] = {
    { "A", ns_t_a },
    { "AAAA", ns_t_aaaa },
    { "CNAME", ns_t_cname },
    { "MX", ns_t_mx },
    { "NS", ns_t_ns },
    { "TXT", ns_t_txt },
    { "SOA", ns_t_soa },
    { "CAA", RECORD_TYPE_CAA },
};
const int dns_record_type_count = sizeof dns_record_types / sizeof dns_record_types[0];

enum { ANSWER_BUFFER_SIZE = 65535, MAX_HOST_NAME_LENGTH = 253 };

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
/* Record data as text                                                      */
/* ------------------------------------------------------------------------ */

/* What every formatter needs: the whole message (names inside rdata point
 * back into it) and the record's own data. */
typedef struct rdata_view {
    const unsigned char *message;
    const unsigned char *message_end;
    const unsigned char *data;
    size_t length;
} rdata_view;

static bool expand_name(const rdata_view *view, const unsigned char *at, char *out, size_t capacity, int *consumed) {
    int used = dn_expand(view->message, view->message_end, at, out, (int)capacity);
    if (used < 0) return false;
    if (consumed) *consumed = used;
    if (out[0] == '\0') snprintf(out, capacity, ".");   /* the root */
    return true;
}

static bool format_address(const rdata_view *view, char *out, size_t capacity) {
    int family = view->length == 4 ? AF_INET : view->length == 16 ? AF_INET6 : 0;
    return family && inet_ntop(family, view->data, out, (socklen_t)capacity) != NULL;
}

static bool format_host_name(const rdata_view *view, char *out, size_t capacity) {
    return expand_name(view, view->data, out, capacity, NULL);
}

static bool format_mail_exchanger(const rdata_view *view, char *out, size_t capacity) {
    char exchanger[NS_MAXDNAME];
    if (view->length < 3) return false;
    unsigned preference = ns_get16(view->data);
    if (!expand_name(view, view->data + 2, exchanger, sizeof exchanger, NULL)) return false;
    snprintf(out, capacity, "%u %s", preference, exchanger);
    return true;
}

static void append_printable(char *out, size_t capacity, size_t *used, const unsigned char *text, size_t length) {
    for (size_t i = 0; i < length && *used + 1 < capacity; i++) {
        unsigned char c = text[i];
        out[(*used)++] = (c >= 0x20 && c != 0x7f) ? (char)c : '?';
    }
    out[*used] = '\0';
}

/* A TXT record is a list of strings of up to 255 bytes each. SPF, DKIM and
 * DMARC read them joined without a separator, so that is how they are shown. */
static bool format_text(const rdata_view *view, char *out, size_t capacity) {
    size_t used = 0, offset = 0;
    out[0] = '\0';
    while (offset < view->length) {
        size_t piece_length = view->data[offset++];
        if (offset + piece_length > view->length) return false;
        append_printable(out, capacity, &used, view->data + offset, piece_length);
        offset += piece_length;
    }
    return true;
}

static bool format_start_of_authority(const rdata_view *view, char *out, size_t capacity) {
    char primary_server[NS_MAXDNAME], responsible_mailbox[NS_MAXDNAME];
    int consumed = 0, offset = 0;
    if (!expand_name(view, view->data, primary_server, sizeof primary_server, &consumed)) return false;
    offset += consumed;
    if (!expand_name(view, view->data + offset, responsible_mailbox, sizeof responsible_mailbox, &consumed)) return false;
    offset += consumed;
    if ((size_t)offset + 20 > view->length) return false;

    const unsigned char *timers = view->data + offset;
    snprintf(out, capacity, "%s %s serial %lu, refresh %lu, retry %lu, expire %lu, minimum %lu",
             primary_server, responsible_mailbox,
             (unsigned long)ns_get32(timers), (unsigned long)ns_get32(timers + 4),
             (unsigned long)ns_get32(timers + 8), (unsigned long)ns_get32(timers + 12),
             (unsigned long)ns_get32(timers + 16));
    return true;
}

/* CAA: flags, tag length, tag, then the value up to the end of the data. */
static bool format_certification_authority(const rdata_view *view, char *out, size_t capacity) {
    if (view->length < 2) return false;
    unsigned flags = view->data[0];
    size_t tag_length = view->data[1];
    if (2 + tag_length > view->length) return false;

    int prefix_length = snprintf(out, capacity, "%u %.*s \"", flags, (int)tag_length, (const char *)view->data + 2);
    if (prefix_length < 0 || (size_t)prefix_length >= capacity) return false;
    size_t used = (size_t)prefix_length;
    append_printable(out, capacity, &used, view->data + 2 + tag_length, view->length - 2 - tag_length);
    if (used + 1 < capacity) { out[used++] = '"'; out[used] = '\0'; }
    return true;
}

static void format_record_data(int type_code, const rdata_view *view, char *out, size_t capacity) {
    bool formatted = false;
    switch (type_code) {
    case ns_t_a:
    case ns_t_aaaa: formatted = format_address(view, out, capacity); break;
    case ns_t_cname:
    case ns_t_ns:
    case ns_t_ptr: formatted = format_host_name(view, out, capacity); break;
    case ns_t_mx: formatted = format_mail_exchanger(view, out, capacity); break;
    case ns_t_txt: formatted = format_text(view, out, capacity); break;
    case ns_t_soa: formatted = format_start_of_authority(view, out, capacity); break;
    case RECORD_TYPE_CAA: formatted = format_certification_authority(view, out, capacity); break;
    default: break;
    }
    if (!formatted) snprintf(out, capacity, "(%zu bytes, not decoded)", view->length);
}

static void describe_type(int type_code, char *out, size_t capacity) {
    for (int i = 0; i < dns_record_type_count; i++) {
        if (dns_record_types[i].code != type_code) continue;
        snprintf(out, capacity, "%s", dns_record_types[i].label);
        return;
    }
    snprintf(out, capacity, "TYPE%d", type_code);
}

/* ------------------------------------------------------------------------ */
/* Query                                                                    */
/* ------------------------------------------------------------------------ */

static dns_status status_from_resolver_error(int resolver_error) {
    switch (resolver_error) {
    case HOST_NOT_FOUND: return DNS_STATUS_NO_SUCH_DOMAIN;
    case NO_DATA: return DNS_STATUS_NO_DATA;
    default: return DNS_STATUS_FAILURE;
    }
}

static void close_resolver(res_state resolver) {
#ifdef __APPLE__
    res_ndestroy(resolver);
#else
    res_nclose(resolver);
#endif
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

/* A CNAME comes back with the answer for every type asked, so the same
 * record can arrive several times; it is kept once. */
static void append_answer(const ns_msg *message, const ns_rr *answer, dns_record_list *list) {
    if (list->count >= DNS_MAX_RECORDS) return;
    dns_record *record = &list->records[list->count];
    rdata_view view = {
        .message = ns_msg_base(*message),
        .message_end = ns_msg_end(*message),
        .data = ns_rr_rdata(*answer),
        .length = ns_rr_rdlen(*answer),
    };
    describe_type(ns_rr_type(*answer), record->type, sizeof record->type);
    snprintf(record->name, sizeof record->name, "%s", ns_rr_name(*answer));
    record->ttl_seconds = (unsigned long)ns_rr_ttl(*answer);
    format_record_data(ns_rr_type(*answer), &view, record->value, sizeof record->value);
    if (!list_contains(list, record)) list->count++;
}

static dns_status parse_answers(const unsigned char *answer, int answer_length, dns_record_list *list) {
    ns_msg message;
    if (ns_initparse(answer, answer_length, &message) < 0) return DNS_STATUS_FAILURE;

    int answer_count = ns_msg_count(message, ns_s_an);
    for (int i = 0; i < answer_count; i++) {
        ns_rr record;
        if (ns_parserr(&message, ns_s_an, i, &record) < 0) return DNS_STATUS_FAILURE;
        append_answer(&message, &record, list);
    }
    return answer_count > 0 ? DNS_STATUS_OK : DNS_STATUS_NO_DATA;
}

/* Points the resolver at one server instead of the system's list. */
static bool use_server(res_state resolver, const dns_server *server) {
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(NS_DEFAULTPORT) };
#ifdef __APPLE__
    address.sin_len = sizeof address;
#endif
    if (inet_pton(AF_INET, server->address, &address.sin_addr) != 1) return false;
#ifdef __APPLE__
    union res_sockaddr_union server_address = { .sin = address };
    res_setservers(resolver, &server_address, 1);
#else
    resolver->nsaddr_list[0] = address;
    resolver->nscount = 1;
#endif
    return true;
}

dns_status dns_query(const dns_server *server, const char *name, int type_code, dns_record_list *list) {
    static __thread unsigned char answer[ANSWER_BUFFER_SIZE];
    struct __res_state resolver;
    memset(&resolver, 0, sizeof resolver);
    if (res_ninit(&resolver) != 0) return DNS_STATUS_FAILURE;
    if (server && !use_server(&resolver, server)) {
        close_resolver(&resolver);
        return DNS_STATUS_FAILURE;
    }

    int answer_length = res_nquery(&resolver, name, ns_c_in, type_code, answer, sizeof answer);
    dns_status status = answer_length < 0 ? status_from_resolver_error(resolver.res_h_errno)
                                          : parse_answers(answer, answer_length, list);
    close_resolver(&resolver);
    return status;
}
