/* Reads a DMARC aggregate report file as receivers send it: plain XML, XML
 * compressed with gzip (Microsoft, Yahoo) or XML inside a zip archive
 * (Google). The kind is told by the file's first bytes, not its name. */
#ifndef REPORT_FILE_H
#define REPORT_FILE_H

#include <stdbool.h>
#include <stddef.h>

/* Why a report could not be read; the UI words it in its language. */
typedef enum report_error {
    REPORT_ERROR_NONE = 0,
    REPORT_ERROR_CANNOT_OPEN,
    REPORT_ERROR_CANNOT_READ,
    REPORT_ERROR_TOO_LARGE,
    REPORT_ERROR_BROKEN_ARCHIVE,   /* a zip or gzip file that does not unpack */
    REPORT_ERROR_NOT_XML,
    REPORT_ERROR_NOT_A_REPORT,     /* XML, but no <feedback> element */
    REPORT_ERROR_OUT_OF_MEMORY,
} report_error;

typedef struct report_text {
    char *data;                  /* zero terminated; free() it */
    size_t length;
} report_text;

/* Returns false and sets `error` when the file cannot be read or unpacked. */
bool report_file_read_xml(const char *path, report_text *xml, report_error *error);

/* The same for bytes already in memory, e.g. from a test. */
bool report_bytes_to_xml(const unsigned char *bytes, size_t length, report_text *xml, report_error *error);

#endif
