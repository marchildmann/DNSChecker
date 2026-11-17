#include "dns_wire.h"

#include "dns_lookup_internal.h"

#include <stdio.h>
#include <string.h>

enum {
    HEADER_SIZE = 12,
    FLAG_RECURSION_DESIRED = 0x0100,
    FLAG_RESPONSE = 0x8000,
    FLAG_TRUNCATED = 0x0200,
    RCODE_MASK = 0x000f,
    RCODE_NO_ERROR = 0,
    RCODE_NAME_ERROR = 3,
    CLASS_INTERNET = 1,
    MAX_LABEL_LENGTH = 63,
    MAX_COMPRESSION_JUMPS = 32,   /* a pointer loop would otherwise never end */
};

static uint16_t read_u16(const unsigned char *at) { return (uint16_t)(at[0] << 8 | at[1]); }
static uint32_t read_u32(const unsigned char *at) {
    return (uint32_t)at[0] << 24 | (uint32_t)at[1] << 16 | (uint32_t)at[2] << 8 | (uint32_t)at[3];
}
static void write_u16(unsigned char *at, uint16_t value) {
    at[0] = (unsigned char)(value >> 8);
    at[1] = (unsigned char)value;
}

/* ------------------------------------------------------------------------ */
/* Query                                                                    */
/* ------------------------------------------------------------------------ */

/* "www.example.com" becomes 3www7example3com0. */
static size_t write_name(const char *name, unsigned char *out, size_t capacity) {
    size_t used = 0;
    while (*name) {
        size_t label_length = strcspn(name, ".");
        if (label_length == 0 || label_length > MAX_LABEL_LENGTH || used + 1 + label_length >= capacity) return 0;
        out[used++] = (unsigned char)label_length;
        memcpy(out + used, name, label_length);
        used += label_length;
        name += label_length + (name[label_length] == '.');
    }
    out[used++] = 0;
    return used;
}

size_t dns_wire_build_query(uint16_t id, const char *name, int type_code, unsigned char *out, size_t capacity) {
    if (capacity < HEADER_SIZE + 4) return 0;
    memset(out, 0, HEADER_SIZE);
    write_u16(out, id);
    write_u16(out + 2, FLAG_RECURSION_DESIRED);
    write_u16(out + 4, 1);   /* one question */

    size_t name_length = write_name(name, out + HEADER_SIZE, capacity - HEADER_SIZE - 4);
    if (name_length == 0) return 0;
    unsigned char *question_end = out + HEADER_SIZE + name_length;
    write_u16(question_end, (uint16_t)type_code);
    write_u16(question_end + 2, CLASS_INTERNET);
    return HEADER_SIZE + name_length + 4;
}

/* ------------------------------------------------------------------------ */
/* Response                                                                 */
/* ------------------------------------------------------------------------ */

typedef struct wire_reader {
    const unsigned char *message;
    size_t length;
} wire_reader;

/* Appends one label and a dot to `out`. */
static bool append_label(const unsigned char *label, size_t label_length, char *out, size_t capacity, size_t *used) {
    if (*used + label_length + 2 > capacity) return false;
    memcpy(out + *used, label, label_length);
    *used += label_length;
    out[(*used)++] = '.';
    return true;
}

/* Reads the name at `offset`, following compression pointers. `next` is
 * set to the offset after the name where it starts, not where a pointer
 * leads. The name is written without its final dot, "." for the root. */
static bool read_name(const wire_reader *reader, size_t offset, char *out, size_t capacity, size_t *next) {
    size_t used = 0;
    bool has_jumped = false;
    for (int jumps = 0; jumps <= MAX_COMPRESSION_JUMPS; ) {
        if (offset >= reader->length) return false;
        unsigned char length_byte = reader->message[offset];
        if (length_byte == 0) {
            if (!has_jumped) *next = offset + 1;
            if (used == 0) snprintf(out, capacity, ".");   /* the root */
            else out[used - 1] = '\0';                      /* in place of the last dot */
            return true;
        }
        if ((length_byte & 0xc0) == 0xc0) {
            if (offset + 1 >= reader->length) return false;
            if (!has_jumped) *next = offset + 2;
            has_jumped = true;
            offset = read_u16(reader->message + offset) & 0x3fff;
            jumps++;
            continue;
        }
        if (length_byte > MAX_LABEL_LENGTH || offset + 1 + length_byte > reader->length) return false;
        if (!append_label(reader->message + offset + 1, length_byte, out, capacity, &used)) return false;
        offset += 1 + (size_t)length_byte;
    }
    return false;
}

static void format_answer_data(const wire_reader *reader, int type_code, size_t data_offset, size_t data_length,
                               char *out, size_t capacity) {
    size_t unused;
    const unsigned char *data = reader->message + data_offset;
    bool formatted = false;
    if (type_code == RECORD_TYPE_CAA) formatted = dns_format_certification_authority(data, data_length, out, capacity);
    else if (type_code == RECORD_TYPE_CNAME) formatted = read_name(reader, data_offset, out, capacity, &unused);
    if (!formatted) dns_format_undecoded(data_length, out, capacity);
}

/* Reads one answer at `*offset` into the list and moves past it. */
static bool read_answer(const wire_reader *reader, size_t *offset, dns_record_list *list) {
    char name[DNS_DOMAIN_CAPACITY], value[DNS_VALUE_CAPACITY];
    if (!read_name(reader, *offset, name, sizeof name, offset)) return false;
    if (*offset + 10 > reader->length) return false;

    const unsigned char *fixed = reader->message + *offset;
    int type_code = read_u16(fixed);
    uint32_t ttl_seconds = read_u32(fixed + 4);
    size_t data_length = read_u16(fixed + 8);
    size_t data_offset = *offset + 10;
    if (data_offset + data_length > reader->length) return false;

    format_answer_data(reader, type_code, data_offset, data_length, value, sizeof value);
    dns_record_list_add(list, type_code, name, ttl_seconds, value);
    *offset = data_offset + data_length;
    return true;
}

static dns_status status_of_header(const unsigned char *message, uint16_t id) {
    uint16_t flags = read_u16(message + 2);
    bool is_our_response = read_u16(message) == id && (flags & FLAG_RESPONSE);
    if (!is_our_response || (flags & FLAG_TRUNCATED)) return DNS_STATUS_FAILURE;
    switch (flags & RCODE_MASK) {
    case RCODE_NO_ERROR: return DNS_STATUS_OK;
    case RCODE_NAME_ERROR: return DNS_STATUS_NO_SUCH_DOMAIN;
    default: return DNS_STATUS_FAILURE;
    }
}

dns_status dns_wire_read_response(const unsigned char *message, size_t length, uint16_t id, dns_record_list *list) {
    char question_name[DNS_DOMAIN_CAPACITY];
    if (length < HEADER_SIZE) return DNS_STATUS_FAILURE;
    dns_status status = status_of_header(message, id);
    if (status != DNS_STATUS_OK) return status;

    wire_reader reader = { message, length };
    size_t offset = HEADER_SIZE;
    int question_count = read_u16(message + 4), answer_count = read_u16(message + 6);
    for (int i = 0; i < question_count; i++) {
        if (!read_name(&reader, offset, question_name, sizeof question_name, &offset)) return DNS_STATUS_FAILURE;
        offset += 4;   /* type and class */
    }
    for (int i = 0; i < answer_count; i++)
        if (!read_answer(&reader, &offset, list)) return DNS_STATUS_FAILURE;
    return answer_count > 0 ? DNS_STATUS_OK : DNS_STATUS_NO_DATA;
}
