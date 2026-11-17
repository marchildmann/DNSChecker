/* Reads a DMARC aggregate report file as receivers send it: plain XML, XML
 * compressed with gzip (Microsoft, Yahoo) or XML inside a zip archive
 * (Google). The kind is told by the file's first bytes, not its name. */
#ifndef REPORT_FILE_H
#define REPORT_FILE_H

#include <stdbool.h>
#include <stddef.h>

typedef struct report_text {
    char *data;                  /* zero terminated; free() it */
    size_t length;
} report_text;

/* Returns false and writes a message to `error` when the file cannot be read
 * or unpacked. */
bool report_file_read_xml(const char *path, report_text *xml, char *error, size_t error_capacity);

/* The same for bytes already in memory, e.g. from a test. */
bool report_bytes_to_xml(const unsigned char *bytes, size_t length, report_text *xml, char *error, size_t error_capacity);

#endif
