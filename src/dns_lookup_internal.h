/* What the per-platform query files share with dns_lookup.c: adding a record
 * to a list, and writing record data as text the same way on every system. */
#ifndef DNS_LOOKUP_INTERNAL_H
#define DNS_LOOKUP_INTERNAL_H

#include "dns_lookup.h"

/* Adds a record unless the list holds the same one already: a CNAME comes
 * back with the answer for every type asked. Records that do not fit are
 * dropped. */
void dns_record_list_add(dns_record_list *list, int type_code, const char *name, unsigned long ttl_seconds,
                         const char *value);

/* Appends bytes as text, with control characters shown as '?'. Keeps the
 * text terminated; `used` is its length so far. */
void dns_append_printable(char *out, size_t capacity, size_t *used, const unsigned char *bytes, size_t length);

void dns_format_mail_exchanger(unsigned preference, const char *exchanger, char *out, size_t capacity);

void dns_format_start_of_authority(const char *primary_server, const char *responsible_mailbox,
                                   const unsigned long timers[5], char *out, size_t capacity);

/* CAA data: flags, tag length, tag, then the value. False when it is cut short. */
bool dns_format_certification_authority(const unsigned char *data, size_t length, char *out, size_t capacity);

/* For data a system could not decode. */
void dns_format_undecoded(size_t length, char *out, size_t capacity);

#endif
