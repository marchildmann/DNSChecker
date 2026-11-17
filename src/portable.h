/* The few calls that differ between Windows and the POSIX systems. */
#ifndef PORTABLE_H
#define PORTABLE_H

#include <stdio.h>
#include <time.h>

/* localtime, but safe to call from several threads. */
void portable_local_time(time_t moment, struct tm *calendar);

/* fopen for a UTF-8 path; Windows' fopen reads paths in the ANSI code page. */
FILE *portable_open_file(const char *utf8_path, const char *mode);

/* The file name at the end of a path, after the last / (or \ on Windows). */
const char *portable_file_name(const char *path);

#endif
