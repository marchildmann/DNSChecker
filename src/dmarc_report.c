#include "dmarc_report.h"

#include "report_file.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static void set_error(char *error, size_t capacity, const char *message) {
    snprintf(error, capacity, "%s", message);
}

bool dmarc_row_passes(const dmarc_report_row *row) {
    return row->dkim_passed || row->spf_passed;
}

/* ------------------------------------------------------------------------ */
/* XML                                                                      */
/* ------------------------------------------------------------------------ */

static xmlNode *child_element(xmlNode *parent, const char *name) {
    if (!parent) return NULL;
    for (xmlNode *child = parent->children; child; child = child->next)
        if (child->type == XML_ELEMENT_NODE && strcmp((const char *)child->name, name) == 0) return child;
    return NULL;
}

/* Follows a path such as "policy_evaluated/dkim" down from `node`. */
static xmlNode *element_at_path(xmlNode *node, const char *path) {
    char name[64];
    while (node && *path) {
        size_t length = strcspn(path, "/");
        snprintf(name, sizeof name, "%.*s", (int)length, path);
        node = child_element(node, name);
        path += length + (path[length] == '/');
    }
    return node;
}

/* The trimmed text at `path`, or "" when the element is missing. */
static void text_at_path(xmlNode *node, const char *path, char *out, size_t capacity) {
    xmlNode *element = element_at_path(node, path);
    xmlChar *content = element ? xmlNodeGetContent(element) : NULL;
    const char *text = content ? (const char *)content : "";
    while (*text == ' ' || *text == '\n' || *text == '\t' || *text == '\r') text++;
    size_t length = strlen(text);
    while (length > 0 && strchr(" \n\t\r", text[length - 1])) length--;
    snprintf(out, capacity, "%.*s", (int)length, text);
    xmlFree(content);
}

static long long number_at_path(xmlNode *node, const char *path) {
    char text[REPORT_SHORT_CAPACITY];
    text_at_path(node, path, text, sizeof text);
    return atoll(text);
}

static bool says_pass(xmlNode *node, const char *path) {
    char result[REPORT_SHORT_CAPACITY];
    text_at_path(node, path, result, sizeof result);
    return strcasecmp(result, "pass") == 0;
}

/* ------------------------------------------------------------------------ */
/* Report                                                                   */
/* ------------------------------------------------------------------------ */

static void read_row(xmlNode *record, dmarc_report_row *row) {
    *row = (dmarc_report_row){ 0 };
    text_at_path(record, "row/source_ip", row->source_ip, sizeof row->source_ip);
    row->message_count = (long)number_at_path(record, "row/count");
    text_at_path(record, "row/policy_evaluated/disposition", row->disposition, sizeof row->disposition);
    row->dkim_passed = says_pass(record, "row/policy_evaluated/dkim");
    row->spf_passed = says_pass(record, "row/policy_evaluated/spf");
    text_at_path(record, "identifiers/header_from", row->header_from, sizeof row->header_from);
    text_at_path(record, "auth_results/dkim/domain", row->dkim_domain, sizeof row->dkim_domain);
    text_at_path(record, "auth_results/dkim/selector", row->dkim_selector, sizeof row->dkim_selector);
    text_at_path(record, "auth_results/spf/domain", row->spf_domain, sizeof row->spf_domain);
}

static int count_records(xmlNode *feedback) {
    int count = 0;
    for (xmlNode *child = feedback->children; child; child = child->next)
        if (child->type == XML_ELEMENT_NODE && strcmp((const char *)child->name, "record") == 0) count++;
    return count;
}

static bool read_rows(xmlNode *feedback, dmarc_report *report) {
    int record_count = count_records(feedback);
    report->rows = record_count ? calloc((size_t)record_count, sizeof *report->rows) : NULL;
    if (record_count && !report->rows) return false;

    for (xmlNode *child = feedback->children; child; child = child->next)
        if (child->type == XML_ELEMENT_NODE && strcmp((const char *)child->name, "record") == 0)
            read_row(child, &report->rows[report->row_count++]);
    return true;
}

static void read_metadata(xmlNode *feedback, dmarc_report *report) {
    text_at_path(feedback, "report_metadata/org_name", report->reporter, sizeof report->reporter);
    text_at_path(feedback, "report_metadata/report_id", report->report_id, sizeof report->report_id);
    report->begin_time = number_at_path(feedback, "report_metadata/date_range/begin");
    report->end_time = number_at_path(feedback, "report_metadata/date_range/end");
    text_at_path(feedback, "policy_published/domain", report->policy_domain, sizeof report->policy_domain);
    text_at_path(feedback, "policy_published/p", report->published_policy, sizeof report->published_policy);
}

/* Entities and network access stay off: the files come from strangers. */
static bool parse_report(const char *xml, size_t length, dmarc_report *report, char *error, size_t error_capacity) {
    *report = (dmarc_report){ 0 };
    xmlDoc *document = xmlReadMemory(xml, (int)length, "report.xml", NULL, XML_PARSE_NONET | XML_PARSE_NOERROR |
                                                                          XML_PARSE_NOWARNING);
    xmlNode *feedback = document ? xmlDocGetRootElement(document) : NULL;
    bool is_feedback = feedback && strcmp((const char *)feedback->name, "feedback") == 0;
    if (!is_feedback) {
        set_error(error, error_capacity, document ? "Kein DMARC-Bericht (kein <feedback>-Element)."
                                                  : "Kein gültiges XML.");
        xmlFreeDoc(document);
        return false;
    }

    read_metadata(feedback, report);
    bool has_rows = read_rows(feedback, report);
    xmlFreeDoc(document);
    if (!has_rows) set_error(error, error_capacity, "Zu wenig Speicher.");
    return has_rows;
}

/* ------------------------------------------------------------------------ */
/* Merging the rows of all reports                                          */
/* ------------------------------------------------------------------------ */

static bool is_same_sender(const dmarc_report_row *first, const dmarc_report_row *second) {
    return strcmp(first->source_ip, second->source_ip) == 0 && strcmp(first->header_from, second->header_from) == 0 &&
           first->dkim_passed == second->dkim_passed && first->spf_passed == second->spf_passed &&
           strcmp(first->dkim_domain, second->dkim_domain) == 0 &&
           strcmp(first->dkim_selector, second->dkim_selector) == 0 && strcmp(first->spf_domain, second->spf_domain) == 0;
}

static int disposition_severity(const char *disposition) {
    if (strcasecmp(disposition, "reject") == 0) return 2;
    if (strcasecmp(disposition, "quarantine") == 0) return 1;
    return 0;
}

static void merge_into(dmarc_report_row *sender, const dmarc_report_row *row) {
    sender->message_count += row->message_count;
    if (disposition_severity(row->disposition) > disposition_severity(sender->disposition))
        snprintf(sender->disposition, sizeof sender->disposition, "%s", row->disposition);
}

static dmarc_report_row *find_sender(dmarc_report_library *library, const dmarc_report_row *row) {
    for (int i = 0; i < library->sender_count; i++)
        if (is_same_sender(&library->senders[i], row)) return &library->senders[i];
    return NULL;
}

static void add_row_to_senders(dmarc_report_library *library, const dmarc_report_row *row) {
    dmarc_report_row *sender = find_sender(library, row);
    if (sender) merge_into(sender, row);
    else library->senders[library->sender_count++] = *row;

    library->total_messages += row->message_count;
    if (dmarc_row_passes(row)) library->passing_messages += row->message_count;
}

/* Failing senders first, as they are what the reader looks for; then the
 * ones sending the most. */
static int compare_senders(const void *first_pointer, const void *second_pointer) {
    const dmarc_report_row *first = first_pointer, *second = second_pointer;
    bool first_passes = dmarc_row_passes(first), second_passes = dmarc_row_passes(second);
    if (first_passes != second_passes) return first_passes ? 1 : -1;
    if (first->message_count != second->message_count) return first->message_count < second->message_count ? 1 : -1;
    return strcmp(first->source_ip, second->source_ip);
}

static void note_time_span(dmarc_report_library *library, const dmarc_report *report) {
    if (library->first_time == 0 || report->begin_time < library->first_time) library->first_time = report->begin_time;
    if (report->end_time > library->last_time) library->last_time = report->end_time;
}

static bool rebuild_senders(dmarc_report_library *library) {
    int row_total = 0;
    for (int i = 0; i < library->report_count; i++) row_total += library->reports[i].row_count;

    free(library->senders);
    library->senders = row_total ? calloc((size_t)row_total, sizeof *library->senders) : NULL;
    library->sender_count = 0;
    library->total_messages = library->passing_messages = 0;
    library->first_time = library->last_time = 0;
    if (row_total && !library->senders) return false;

    for (int i = 0; i < library->report_count; i++) {
        note_time_span(library, &library->reports[i]);
        for (int j = 0; j < library->reports[i].row_count; j++) add_row_to_senders(library, &library->reports[i].rows[j]);
    }
    qsort(library->senders, (size_t)library->sender_count, sizeof *library->senders, compare_senders);
    return true;
}

/* ------------------------------------------------------------------------ */
/* Library                                                                  */
/* ------------------------------------------------------------------------ */

static bool is_already_loaded(const dmarc_report_library *library, const dmarc_report *report) {
    for (int i = 0; i < library->report_count; i++) {
        const dmarc_report *loaded = &library->reports[i];
        if (strcmp(loaded->reporter, report->reporter) == 0 && strcmp(loaded->report_id, report->report_id) == 0)
            return true;
    }
    return false;
}

/* Takes over the report's rows, also when it fails. */
static bool append_report(dmarc_report_library *library, const dmarc_report *report) {
    dmarc_report *grown = realloc(library->reports, (size_t)(library->report_count + 1) * sizeof *grown);
    if (!grown) {
        free(report->rows);
        return false;
    }
    library->reports = grown;
    library->reports[library->report_count++] = *report;
    return rebuild_senders(library);
}

report_add_result dmarc_library_add_xml(dmarc_report_library *library, const char *xml, size_t length, char *error,
                                        size_t error_capacity) {
    dmarc_report report;
    if (!parse_report(xml, length, &report, error, error_capacity)) return REPORT_UNREADABLE;
    if (is_already_loaded(library, &report)) {
        free(report.rows);
        return REPORT_ALREADY_LOADED;
    }
    if (append_report(library, &report)) return REPORT_ADDED;

    set_error(error, error_capacity, "Zu wenig Speicher.");
    return REPORT_UNREADABLE;
}

report_add_result dmarc_library_add_file(dmarc_report_library *library, const char *path, char *error,
                                         size_t error_capacity) {
    report_text xml;
    if (!report_file_read_xml(path, &xml, error, error_capacity)) return REPORT_UNREADABLE;
    report_add_result result = dmarc_library_add_xml(library, xml.data, xml.length, error, error_capacity);
    free(xml.data);
    return result;
}

void dmarc_library_clear(dmarc_report_library *library) {
    for (int i = 0; i < library->report_count; i++) free(library->reports[i].rows);
    free(library->reports);
    free(library->senders);
    *library = (dmarc_report_library){ 0 };
}
