#include "report_file.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

/* Reports are a few kilobytes; anything far larger is not a report, and the
 * limit keeps a crafted archive from unpacking into gigabytes. */
enum { MAX_FILE_SIZE = 20 * 1024 * 1024, MAX_XML_SIZE = 50 * 1024 * 1024 };

enum {
    ZIP_LOCAL_HEADER_SIGNATURE = 0x04034b50,
    ZIP_CENTRAL_HEADER_SIGNATURE = 0x02014b50,
    ZIP_END_SIGNATURE = 0x06054b50,
    ZIP_LOCAL_HEADER_SIZE = 30,
    ZIP_CENTRAL_HEADER_SIZE = 46,
    ZIP_END_RECORD_SIZE = 22,
    ZIP_METHOD_STORED = 0,
    ZIP_METHOD_DEFLATED = 8,
};

static void set_error(char *error, size_t capacity, const char *message) {
    snprintf(error, capacity, "%s", message);
}

static bool copy_as_text(const unsigned char *bytes, size_t length, report_text *xml) {
    xml->data = malloc(length + 1);
    if (!xml->data) return false;
    memcpy(xml->data, bytes, length);
    xml->data[length] = '\0';
    xml->length = length;
    return true;
}

/* ------------------------------------------------------------------------ */
/* Inflating                                                                */
/* ------------------------------------------------------------------------ */

/* `window_bits` picks the wrapper: 16 + MAX_WBITS reads gzip, -MAX_WBITS
 * reads the bare deflate data inside a zip entry. */
/* Doubles the buffer up to MAX_XML_SIZE; frees it and returns NULL beyond. */
static char *grow_text_buffer(char *text, size_t *capacity) {
    *capacity *= 2;
    char *grown = *capacity <= MAX_XML_SIZE ? realloc(text, *capacity) : NULL;
    if (!grown) free(text);
    return grown;
}

static bool inflate_to_text(const unsigned char *bytes, size_t length, int window_bits, report_text *xml) {
    z_stream stream = { .next_in = (Bytef *)bytes, .avail_in = (uInt)length };
    if (inflateInit2(&stream, window_bits) != Z_OK) return false;

    size_t capacity = length * 8 + 1024, used = 0;
    if (capacity > MAX_XML_SIZE) capacity = MAX_XML_SIZE;
    char *text = malloc(capacity);
    int status = Z_OK;
    while (text && status == Z_OK) {
        if (capacity - used < 1024) text = grow_text_buffer(text, &capacity);
        if (!text) break;
        stream.next_out = (Bytef *)text + used;
        stream.avail_out = (uInt)(capacity - used - 1);
        status = inflate(&stream, Z_NO_FLUSH);
        used = capacity - 1 - stream.avail_out;
    }
    inflateEnd(&stream);
    if (!text || status != Z_STREAM_END) { free(text); return false; }

    text[used] = '\0';
    xml->data = text;
    xml->length = used;
    return true;
}

/* ------------------------------------------------------------------------ */
/* Zip                                                                      */
/* ------------------------------------------------------------------------ */

static uint16_t read_u16(const unsigned char *at) { return (uint16_t)(at[0] | at[1] << 8); }
static uint32_t read_u32(const unsigned char *at) {
    return (uint32_t)at[0] | (uint32_t)at[1] << 8 | (uint32_t)at[2] << 16 | (uint32_t)at[3] << 24;
}

/* What the central directory says about the archive's first file; its sizes
 * are reliable even when the local header leaves them out (flag bit 3). */
typedef struct zip_entry {
    uint16_t method;
    uint32_t compressed_size;
    uint32_t local_header_offset;
} zip_entry;

static const unsigned char *find_zip_end_record(const unsigned char *bytes, size_t length) {
    if (length < ZIP_END_RECORD_SIZE) return NULL;
    for (size_t offset = length - ZIP_END_RECORD_SIZE + 1; offset-- > 0;)
        if (read_u32(bytes + offset) == ZIP_END_SIGNATURE) return bytes + offset;
    return NULL;
}

static bool read_first_zip_entry(const unsigned char *bytes, size_t length, zip_entry *entry) {
    const unsigned char *end_record = find_zip_end_record(bytes, length);
    if (!end_record) return false;
    uint32_t directory_offset = read_u32(end_record + 16);
    if ((size_t)directory_offset + ZIP_CENTRAL_HEADER_SIZE > length) return false;

    const unsigned char *header = bytes + directory_offset;
    if (read_u32(header) != ZIP_CENTRAL_HEADER_SIGNATURE) return false;
    entry->method = read_u16(header + 10);
    entry->compressed_size = read_u32(header + 20);
    entry->local_header_offset = read_u32(header + 42);
    return true;
}

static bool unzip_first_file(const unsigned char *bytes, size_t length, report_text *xml, char *error, size_t error_capacity) {
    zip_entry entry;
    if (!read_first_zip_entry(bytes, length, &entry)) {
        set_error(error, error_capacity, "Das Zip-Archiv ist beschädigt.");
        return false;
    }
    size_t header_offset = entry.local_header_offset;
    if (header_offset + ZIP_LOCAL_HEADER_SIZE > length || read_u32(bytes + header_offset) != ZIP_LOCAL_HEADER_SIGNATURE) {
        set_error(error, error_capacity, "Das Zip-Archiv ist beschädigt.");
        return false;
    }
    size_t data_offset = header_offset + ZIP_LOCAL_HEADER_SIZE + read_u16(bytes + header_offset + 26) +
                         read_u16(bytes + header_offset + 28);
    if (data_offset + entry.compressed_size > length) {
        set_error(error, error_capacity, "Das Zip-Archiv ist unvollständig.");
        return false;
    }

    const unsigned char *data = bytes + data_offset;
    bool unpacked = entry.method == ZIP_METHOD_STORED   ? copy_as_text(data, entry.compressed_size, xml)
                    : entry.method == ZIP_METHOD_DEFLATED ? inflate_to_text(data, entry.compressed_size, -MAX_WBITS, xml)
                                                          : false;
    if (!unpacked) set_error(error, error_capacity, "Das Zip-Archiv lässt sich nicht entpacken.");
    return unpacked;
}

/* ------------------------------------------------------------------------ */
/* Entry points                                                             */
/* ------------------------------------------------------------------------ */

static bool is_zip(const unsigned char *bytes, size_t length) {
    return length >= 4 && read_u32(bytes) == ZIP_LOCAL_HEADER_SIGNATURE;
}

static bool is_gzip(const unsigned char *bytes, size_t length) {
    return length >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b;
}

bool report_bytes_to_xml(const unsigned char *bytes, size_t length, report_text *xml, char *error, size_t error_capacity) {
    *xml = (report_text){ 0 };
    if (is_zip(bytes, length)) return unzip_first_file(bytes, length, xml, error, error_capacity);
    if (is_gzip(bytes, length)) {
        bool unpacked = inflate_to_text(bytes, length, 16 + MAX_WBITS, xml);
        if (!unpacked) set_error(error, error_capacity, "Die gz-Datei lässt sich nicht entpacken.");
        return unpacked;
    }
    if (!copy_as_text(bytes, length, xml)) {
        set_error(error, error_capacity, "Zu wenig Speicher.");
        return false;
    }
    return true;
}

static unsigned char *read_whole_file(const char *path, size_t *length, char *error, size_t error_capacity) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        set_error(error, error_capacity, "Die Datei lässt sich nicht öffnen.");
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);
    unsigned char *bytes = (size > 0 && size <= MAX_FILE_SIZE) ? malloc((size_t)size) : NULL;
    bool was_read = bytes && fread(bytes, 1, (size_t)size, file) == (size_t)size;
    fclose(file);

    if (!was_read) {
        free(bytes);
        set_error(error, error_capacity, size > MAX_FILE_SIZE ? "Die Datei ist zu groß für einen Bericht."
                                                              : "Die Datei lässt sich nicht lesen.");
        return NULL;
    }
    *length = (size_t)size;
    return bytes;
}

bool report_file_read_xml(const char *path, report_text *xml, char *error, size_t error_capacity) {
    size_t length = 0;
    unsigned char *bytes = read_whole_file(path, &length, error, error_capacity);
    if (!bytes) return false;
    bool converted = report_bytes_to_xml(bytes, length, xml, error, error_capacity);
    free(bytes);
    return converted;
}
