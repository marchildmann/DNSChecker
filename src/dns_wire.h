/* DNS messages in wire format (RFC 1035, section 4), built and read by the
 * app itself. Windows needs this for CAA: its DNS API answers a CAA query
 * with success but drops the records, as it drops every type it does not
 * know. Plain C without sockets, so the tests run it on any system. */
#ifndef DNS_WIRE_H
#define DNS_WIRE_H

#include "dns_lookup.h"

#include <stddef.h>
#include <stdint.h>

enum { DNS_WIRE_MESSAGE_CAPACITY = 4096 };

/* Writes a query for `name` and `type_code` that asks for recursion.
 * Returns its length, or 0 when the name does not fit or has an empty label. */
size_t dns_wire_build_query(uint16_t id, const char *name, int type_code, unsigned char *out, size_t capacity);

/* Reads the answer section of a response to the query `id` into `list`:
 * CAA and CNAME records as text, other types as undecoded. Malformed or
 * truncated messages, and responses to another query, give DNS_STATUS_FAILURE. */
dns_status dns_wire_read_response(const unsigned char *message, size_t length, uint16_t id, dns_record_list *list);

#endif
