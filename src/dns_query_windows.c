/* dns_query for Windows: the system's DNS API (DnsQuery_UTF8), which hands
 * back each record already taken apart. The cache is bypassed so a query
 * shows what the server holds now, as on the other systems. */
#include "dns_lookup.h"

#include "dns_lookup_internal.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windns.h>
#include <stddef.h>
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

/* Windows has no structure for CAA and hands over the raw data. Depending on
 * the version it is prefixed with its byte count (DNS_UNKNOWN_DATA) or not;
 * the record's data length tells which. */
static void format_certification_authority(const DNS_RECORDA *record, char *out, size_t capacity) {
    const DNS_UNKNOWN_DATA *unknown = &record->Data.Unknown;
    size_t prefixed_length = offsetof(DNS_UNKNOWN_DATA, bData) + unknown->dwByteCount;
    bool has_count_prefix = record->wDataLength >= offsetof(DNS_UNKNOWN_DATA, bData) &&
                            prefixed_length == record->wDataLength;
    const unsigned char *data = has_count_prefix ? unknown->bData : (const unsigned char *)&record->Data;
    size_t length = has_count_prefix ? unknown->dwByteCount : record->wDataLength;
    if (!dns_format_certification_authority(data, length, out, capacity)) dns_format_undecoded(length, out, capacity);
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
    case RECORD_TYPE_CAA: format_certification_authority(record, out, capacity); break;
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

dns_status dns_query(const dns_server *server, const char *name, int type_code, dns_record_list *list) {
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
