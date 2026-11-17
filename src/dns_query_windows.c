/* dns_query for Windows: the system's DNS API (DnsQuery_UTF8), which hands
 * back each record already taken apart. The cache is bypassed so a query
 * shows what the server holds now, as on the other systems.
 *
 * CAA is the exception: the API answers such a query with success and no
 * records, as it drops every type it does not know. CAA queries therefore
 * go out as UDP packets the app builds and reads itself (dns_wire.c). */
#include "dns_lookup.h"

#include "dns_lookup_internal.h"
#include "dns_wire.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Record data                                                              */
/* ------------------------------------------------------------------------ */

static void format_address(int family, const void *address, char *out, size_t capacity) {
    if (!inet_ntop(family, address, out, capacity)) dns_format_undecoded(family == AF_INET ? 4 : 16, out, capacity);
}

/* SPF, DKIM and DMARC read the strings of a TXT record joined without a
 * separator, so that is how they are shown. */
static void format_text(const DNS_TXT_DATAA *text, char *out, size_t capacity) {
    size_t used = 0;
    out[0] = '\0';
    for (DWORD i = 0; i < text->dwStringCount; i++) {
        const char *piece = text->pStringArray[i];
        dns_append_printable(out, capacity, &used, (const unsigned char *)piece, strlen(piece));
    }
}

static void format_start_of_authority(const DNS_SOA_DATAA *soa, char *out, size_t capacity) {
    const unsigned long timers[5] = { soa->dwSerialNo, soa->dwRefresh, soa->dwRetry, soa->dwExpire, soa->dwDefaultTtl };
    dns_format_start_of_authority(soa->pNamePrimaryServer, soa->pNameAdministrator, timers, out, capacity);
}

static void format_record_data(const DNS_RECORDA *record, char *out, size_t capacity) {
    switch (record->wType) {
    case RECORD_TYPE_A: format_address(AF_INET, &record->Data.A.IpAddress, out, capacity); break;
    case RECORD_TYPE_AAAA: format_address(AF_INET6, &record->Data.AAAA.Ip6Address, out, capacity); break;
    case RECORD_TYPE_CNAME:
    case RECORD_TYPE_NS:
    case RECORD_TYPE_PTR: snprintf(out, capacity, "%s", record->Data.PTR.pNameHost); break;
    case RECORD_TYPE_MX:
        dns_format_mail_exchanger(record->Data.MX.wPreference, record->Data.MX.pNameExchange, out, capacity);
        break;
    case RECORD_TYPE_TXT: format_text(&record->Data.TXT, out, capacity); break;
    case RECORD_TYPE_SOA: format_start_of_authority(&record->Data.SOA, out, capacity); break;
    default: dns_format_undecoded(record->wDataLength, out, capacity); break;
    }
}

/* ------------------------------------------------------------------------ */
/* Query                                                                    */
/* ------------------------------------------------------------------------ */

static dns_status status_from_error(DNS_STATUS error) {
    switch (error) {
    case ERROR_SUCCESS: return DNS_STATUS_OK;
    case DNS_ERROR_RCODE_NAME_ERROR: return DNS_STATUS_NO_SUCH_DOMAIN;
    case DNS_INFO_NO_RECORDS: return DNS_STATUS_NO_DATA;
    default: return DNS_STATUS_FAILURE;
    }
}

/* The list holds every section of the answer; only the answers count, as on
 * the other systems. */
static dns_status add_answers(const DNS_RECORDA *first, dns_record_list *list) {
    char value[DNS_VALUE_CAPACITY];
    int answer_count = 0;
    for (const DNS_RECORDA *record = first; record; record = record->pNext) {
        if (record->Flags.S.Section != DnsSectionAnswer) continue;
        format_record_data(record, value, sizeof value);
        dns_record_list_add(list, record->wType, record->pName, record->dwTtl, value);
        answer_count++;
    }
    return answer_count > 0 ? DNS_STATUS_OK : DNS_STATUS_NO_DATA;
}

/* ------------------------------------------------------------------------ */
/* CAA over UDP                                                             */
/* ------------------------------------------------------------------------ */

enum { UDP_ATTEMPTS = 3, UDP_TIMEOUT_MILLISECONDS = 3000, DNS_PORT = 53 };

/* The first DNS server Windows uses, for queries that name none. */
static bool find_system_name_server(struct in_addr *address) {
    unsigned char buffer[1024];
    DWORD size = sizeof buffer;
    if (DnsQueryConfig(DnsConfigDnsServerList, 0, NULL, NULL, buffer, &size) != ERROR_SUCCESS) return false;
    const IP4_ARRAY *servers = (const IP4_ARRAY *)buffer;
    if (servers->AddrCount == 0) return false;
    address->s_addr = servers->AddrArray[0];
    return true;
}

static bool find_target_server(const dns_server *server, struct sockaddr_in *target) {
    *target = (struct sockaddr_in){ .sin_family = AF_INET, .sin_port = htons(DNS_PORT) };
    if (server) return inet_pton(AF_INET, server->address, &target->sin_addr) == 1;
    return find_system_name_server(&target->sin_addr);
}

/* Sends the query and waits for the answer, a few times over, since UDP
 * may lose either. Returns the answer's length, or 0. */
static int exchange_over_udp(const struct sockaddr_in *target, const unsigned char *query, int query_length,
                             unsigned char *answer, int capacity) {
    SOCKET udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp == INVALID_SOCKET) return 0;
    DWORD timeout = UDP_TIMEOUT_MILLISECONDS;
    setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout);

    int answer_length = 0;
    for (int attempt = 0; attempt < UDP_ATTEMPTS && answer_length <= 0; attempt++) {
        if (sendto(udp, (const char *)query, query_length, 0, (const struct sockaddr *)target, sizeof *target) < 0)
            break;
        answer_length = recv(udp, (char *)answer, capacity, 0);
    }
    closesocket(udp);
    return answer_length > 0 ? answer_length : 0;
}

static dns_status query_over_udp(const dns_server *server, const char *name, int type_code, dns_record_list *list) {
    unsigned char query[DNS_WIRE_MESSAGE_CAPACITY], answer[DNS_WIRE_MESSAGE_CAPACITY];
    struct sockaddr_in target;
    uint16_t id = (uint16_t)(GetTickCount() ^ GetCurrentThreadId());
    size_t query_length = dns_wire_build_query(id, name, type_code, query, sizeof query);
    if (query_length == 0 || !find_target_server(server, &target)) return DNS_STATUS_FAILURE;

    WSADATA winsock;
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) return DNS_STATUS_FAILURE;
    int answer_length = exchange_over_udp(&target, query, (int)query_length, answer, sizeof answer);
    WSACleanup();
    if (answer_length == 0) return DNS_STATUS_FAILURE;
    return dns_wire_read_response(answer, (size_t)answer_length, id, list);
}

/* ------------------------------------------------------------------------ */
/* Entry point                                                              */
/* ------------------------------------------------------------------------ */

dns_status dns_query(const dns_server *server, const char *name, int type_code, dns_record_list *list) {
    if (type_code == RECORD_TYPE_CAA) return query_over_udp(server, name, type_code, list);

    IP4_ARRAY servers = { .AddrCount = 1 };
    if (server && inet_pton(AF_INET, server->address, &servers.AddrArray[0]) != 1) return DNS_STATUS_FAILURE;

    DNS_RECORDA *records = NULL;
    DWORD options = DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE;
    DNS_STATUS error = DnsQuery_UTF8(name, (WORD)type_code, options, server ? &servers : NULL, &records, NULL);
    dns_status status = status_from_error(error);
    if (status == DNS_STATUS_OK) status = add_answers(records, list);
    if (records) DnsRecordListFree((DNS_RECORD *)records, DnsFreeRecordList);
    return status;
}
