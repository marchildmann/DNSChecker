/* dns_query for macOS and Linux: libresolv sends the query, and the answer
 * is read from the wire format with ns_initparse and dn_expand. */
#include "dns_lookup.h"

#include "dns_lookup_internal.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <netinet/in.h>
#include <resolv.h>
#include <stdio.h>
#include <string.h>

enum { ANSWER_BUFFER_SIZE = 65535 };

/* ------------------------------------------------------------------------ */
/* Record data in wire format                                               */
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
    dns_format_mail_exchanger(preference, exchanger, out, capacity);
    return true;
}

/* A TXT record is a list of strings of up to 255 bytes each. SPF, DKIM and
 * DMARC read them joined without a separator, so that is how they are shown. */
static bool format_text(const rdata_view *view, char *out, size_t capacity) {
    size_t used = 0, offset = 0;
    out[0] = '\0';
    while (offset < view->length) {
        size_t piece_length = view->data[offset++];
        if (offset + piece_length > view->length) return false;
        dns_append_printable(out, capacity, &used, view->data + offset, piece_length);
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

    const unsigned char *at = view->data + offset;
    unsigned long timers[5];
    for (int i = 0; i < 5; i++) timers[i] = (unsigned long)ns_get32(at + 4 * i);
    dns_format_start_of_authority(primary_server, responsible_mailbox, timers, out, capacity);
    return true;
}

static void format_record_data(int type_code, const rdata_view *view, char *out, size_t capacity) {
    bool formatted = false;
    switch (type_code) {
    case RECORD_TYPE_A:
    case RECORD_TYPE_AAAA: formatted = format_address(view, out, capacity); break;
    case RECORD_TYPE_CNAME:
    case RECORD_TYPE_NS:
    case RECORD_TYPE_PTR: formatted = format_host_name(view, out, capacity); break;
    case RECORD_TYPE_MX: formatted = format_mail_exchanger(view, out, capacity); break;
    case RECORD_TYPE_TXT: formatted = format_text(view, out, capacity); break;
    case RECORD_TYPE_SOA: formatted = format_start_of_authority(view, out, capacity); break;
    case RECORD_TYPE_CAA: formatted = dns_format_certification_authority(view->data, view->length, out, capacity); break;
    default: break;
    }
    if (!formatted) dns_format_undecoded(view->length, out, capacity);
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

static void append_answer(const ns_msg *message, const ns_rr *answer, dns_record_list *list) {
    char value[DNS_VALUE_CAPACITY];
    rdata_view view = {
        .message = ns_msg_base(*message),
        .message_end = ns_msg_end(*message),
        .data = ns_rr_rdata(*answer),
        .length = ns_rr_rdlen(*answer),
    };
    format_record_data(ns_rr_type(*answer), &view, value, sizeof value);
    dns_record_list_add(list, ns_rr_type(*answer), ns_rr_name(*answer), (unsigned long)ns_rr_ttl(*answer), value);
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
