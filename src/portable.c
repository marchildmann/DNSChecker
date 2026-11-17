#include "portable.h"

#include <string.h>

#ifdef _WIN32
#include <stdlib.h>
#include <windows.h>

void portable_local_time(time_t moment, struct tm *calendar) {
    localtime_s(calendar, &moment);
}

static wchar_t *to_wide(const char *utf8) {
    int length = MultiByteToWideChar(CP_UTF8, 0, utf8, -1, NULL, 0);
    wchar_t *wide = length > 0 ? malloc((size_t)length * sizeof *wide) : NULL;
    if (wide) MultiByteToWideChar(CP_UTF8, 0, utf8, -1, wide, length);
    return wide;
}

FILE *portable_open_file(const char *utf8_path, const char *mode) {
    wchar_t *wide_path = to_wide(utf8_path), *wide_mode = to_wide(mode);
    FILE *file = wide_path && wide_mode ? _wfopen(wide_path, wide_mode) : NULL;
    free(wide_path);
    free(wide_mode);
    return file;
}
#else
void portable_local_time(time_t moment, struct tm *calendar) {
    localtime_r(&moment, calendar);
}

FILE *portable_open_file(const char *utf8_path, const char *mode) {
    return fopen(utf8_path, mode);
}
#endif

const char *portable_file_name(const char *path) {
    const char *name = path;
    for (const char *at = path; *at; at++)
        if (*at == '/' || *at == '\\') name = at + 1;
    return name;
}
