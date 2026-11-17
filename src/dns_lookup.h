/* DNS queries, with each answer turned into a printable record. The query
 * itself is per platform: dns_query_resolv.c (libresolv, macOS and Linux)
 * and dns_query_windows.c (the Windows DNS API); this file's names,
 * normalization and record texts are shared. No UI code here; a query
 * blocks, so call it from a worker thread (see lookup_task.h). */
#ifndef DNS_LOOKUP_H
#define DNS_LOOKUP_H

#include <stdbool.h>
#include <stddef.h>

enum {
    DNS_DOMAIN_CAPACITY = 256,
    DNS_VALUE_CAPACITY = 2048,   /* long TXT records (DKIM keys) need room */
    DNS_MAX_RECORDS = 256,
};

typedef enum dns_status {
    DNS_STATUS_OK = 0,
    DNS_STATUS_NO_DATA,          /* the name exists but has no record of that type */
    DNS_STATUS_NO_SUCH_DOMAIN,   /* NXDOMAIN */
    DNS_STATUS_FAILURE,          /* timeout, server failure, malformed answer */
} dns_status;

typedef struct dns_record {
    char type[12];               /* "A", "MX", "TXT", ... */
    char name[DNS_DOMAIN_CAPACITY];
    unsigned long ttl_seconds;
    char value[DNS_VALUE_CAPACITY];
} dns_record;

typedef struct dns_record_list {
    dns_record records[DNS_MAX_RECORDS];
    int count;
} dns_record_list;

/* The record type numbers (RFC 1035, 3596, 8659); spelled out here so the
 * code does not depend on one platform's resolver headers. Not DNS_TYPE_*:
 * Windows' windns.h defines those as macros. */
enum {
    RECORD_TYPE_A = 1,
    RECORD_TYPE_NS = 2,
    RECORD_TYPE_CNAME = 5,
    RECORD_TYPE_SOA = 6,
    RECORD_TYPE_PTR = 12,
    RECORD_TYPE_MX = 15,
    RECORD_TYPE_TXT = 16,
    RECORD_TYPE_AAAA = 28,
    RECORD_TYPE_CAA = 257,
};

/* The record types the app offers, in the order shown. */
typedef struct dns_record_type {
    const char *label;
    int code;                    /* RECORD_TYPE_* */
} dns_record_type;

extern const dns_record_type dns_record_types[];
extern const int dns_record_type_count;

/* Turns user input such as " https://Example.COM./path " into "example.com".
 * Returns false when nothing that looks like a host name is left. */
bool dns_normalize_domain(const char *input, char *out, size_t capacity);

/* Makes a name the user typed complete: "lp" and "s1._domainkey" get
 * ".<domain>" appended, "@" stands for the domain itself, and a name that
 * already ends in the domain stays as it is. Returns false for invalid names. */
bool dns_qualify_name(const char *entry, const char *domain, char *out, size_t capacity);

/* The reverse, for showing names the way DNS panels do: "@" for the domain,
 * "www" for www.<domain>, and other names unchanged. */
void dns_relative_name(const char *name, const char *domain, char *out, size_t capacity);

/* A name server asked directly, bypassing the system resolver and its cache,
 * so changes to a zone show as soon as the server has them. */
typedef struct dns_server {
    char host_name[DNS_DOMAIN_CAPACITY];   /* "ns1.example.net" */
    char address[48];                      /* its IPv4 address as text */
} dns_server;

/* Asks for records of one type and appends them to `list`. `server` NULL
 * asks the system resolver (cached, follows aliases into other zones).
 * Records that do not fit are dropped. */
dns_status dns_query(const dns_server *server, const char *name, int type_code, dns_record_list *list);

#endif
