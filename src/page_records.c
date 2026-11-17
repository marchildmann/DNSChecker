/* The DNS records page: where the answers came from, the mail
 * authentication summary and a table of every record found, filtered by type. */
#include "app_state.h"

#include <stdio.h>
#include <string.h>

enum { FILTER_ALL_TYPES = 0, MAX_FILTER_LABELS = 16, FILTER_LABEL_CAPACITY = 24 };

static void waiting_state(cui_ctx *ui, const ui_text *text) {
    cui_row(ui, .gap = 10, .pad_y = 24) {
        cui_spinner(ui, 18);
        cui_secondary(ui, text->strings.looking_up);
    }
}

/* ------------------------------------------------------------------------ */
/* Mail authentication summary                                              */
/* ------------------------------------------------------------------------ */

static void summary_card(cui_ctx *ui, const char *title, bool is_present, const char *status, const char *detail) {
    cui_card(ui, .width = CUI_FILL, .gap = 8, .pad = 16) {
        cui_row(ui, .width = CUI_FILL, .gap = 8) {
            cui_label(ui, title);
            cui_spacer(ui);
            cui_badge(ui, status, .tone = is_present ? CUI_TONE_SUCCESS : CUI_TONE_WARNING, .dot = true);
        }
        cui_text(ui, detail, .font = CUI_FONT_MONO, .size = 12, .color = CUI_COLOR_TEXT_SECONDARY);
    }
}

static void dkim_card(cui_ctx *ui, const mail_security_summary *mail, const ui_text *text) {
    char tried[512], detail[1024];
    if (mail->dkim_selector_count > 0) {
        snprintf(detail, sizeof detail, text->formats.dkim_selectors, mail->dkim_selectors);
        summary_card(ui, "DKIM", true, text->strings.present, detail);
        return;
    }
    if (mail->has_unknown_dkim_selectors) {
        summary_card(ui, "DKIM", false, text->strings.name_unknown, text->strings.unknown_dkim_selectors);
        return;
    }
    tried[0] = '\0';
    for (int i = 0; i < scan_common_dkim_selector_count; i++) {
        size_t used = strlen(tried);
        snprintf(tried + used, sizeof tried - used, "%s%s", i ? ", " : "", scan_common_dkim_selectors[i]);
    }
    snprintf(detail, sizeof detail, text->formats.dkim_missing, tried);
    summary_card(ui, "DKIM", false, text->strings.missing, detail);
}

static const char *presence(const ui_text *text, bool is_present) {
    return is_present ? text->strings.present : text->strings.missing;
}

static void mail_summary(cui_ctx *ui, const mail_security_summary *mail, const ui_text *text) {
    char mail_exchangers[64];
    int count = mail->mail_exchanger_count;
    snprintf(mail_exchangers, sizeof mail_exchangers,
             ui_plural(count, text->formats.mail_exchangers_one, text->formats.mail_exchangers_other), count);
    bool has_mail_exchangers = count > 0;

    cui_box(ui, .dir = CUI_GRID, .columns = 4, .min_column_width = 220, .gap = 12, .width = CUI_FILL) {
        summary_card(ui, text->strings.incoming_mail_card, has_mail_exchangers, presence(text, has_mail_exchangers),
                     has_mail_exchangers ? mail_exchangers : text->strings.no_mail_exchanger);
        summary_card(ui, "SPF", mail->has_spf, presence(text, mail->has_spf),
                     mail->has_spf ? mail->spf_record : text->strings.no_spf);
        dkim_card(ui, mail, text);
        summary_card(ui, "DMARC", mail->has_dmarc, presence(text, mail->has_dmarc),
                     mail->has_dmarc ? mail->dmarc_record : text->strings.no_dmarc);
    }
}

/* ------------------------------------------------------------------------ */
/* Record table                                                             */
/* ------------------------------------------------------------------------ */

typedef struct record_filter {
    char labels[MAX_FILTER_LABELS][FILTER_LABEL_CAPACITY];
    const char *label_pointers[MAX_FILTER_LABELS];
    int count;
} record_filter;

static int count_records_of_type(const dns_record_list *records, const char *type) {
    int count = 0;
    for (int i = 0; i < records->count; i++)
        if (strcmp(records->records[i].type, type) == 0) count++;
    return count;
}

/* "All (12)", "A (2)", "MX (1)", ...: the counts tell what is there before a click. */
static void build_record_filter(const dns_record_list *records, const ui_text *text, record_filter *filter) {
    filter->count = 0;
    snprintf(filter->labels[filter->count++], FILTER_LABEL_CAPACITY, text->formats.filter_all, records->count);
    for (int i = 0; i < dns_record_type_count; i++) {
        const char *type = dns_record_types[i].label;
        snprintf(filter->labels[filter->count++], FILTER_LABEL_CAPACITY, "%s (%d)", type,
                 count_records_of_type(records, type));
    }
    for (int i = 0; i < filter->count; i++) filter->label_pointers[i] = filter->labels[i];
}

static bool is_shown_by_filter(const dns_record *record, int filter_index) {
    if (filter_index == FILTER_ALL_TYPES) return true;
    return strcmp(record->type, dns_record_types[filter_index - 1].label) == 0;
}

static void record_row(cui_ctx *ui, const dns_record *record, const char *domain) {
    char shown_name[DNS_DOMAIN_CAPACITY];
    dns_relative_name(record->name, domain, shown_name, sizeof shown_name);

    cui_table_row(ui, false);
    cui_table_cell(ui);
    cui_badge(ui, record->type, .tone = CUI_TONE_ACCENT);
    cui_table_cell(ui);
    cui_text(ui, shown_name, .nowrap = true);
    cui_table_cell_textf(ui, "%lu", record->ttl_seconds);
    cui_table_cell(ui);
    cui_text(ui, record->value, .font = CUI_FONT_MONO, .size = 12, .width = CUI_FILL);
}

static void record_table(cui_ctx *ui, const lookup_report *report, int filter_index, const ui_text *text) {
    const dns_record_list *records = &report->records;
    const cui_table_column columns[] = {
        { text->strings.column_type, CUI_PX(90), CUI_TEXT_LEFT, false },
        { text->strings.column_name, CUI_PX(220), CUI_TEXT_LEFT, false },
        { text->strings.column_ttl, CUI_PX(80), CUI_TEXT_RIGHT, false },
        { text->strings.column_value, CUI_FILL, CUI_TEXT_LEFT, false },
    };
    cui_table(ui, "records", columns, 4, .compact = true, .striped = true) {
        for (int i = 0; i < records->count; i++) {
            if (!is_shown_by_filter(&records->records[i], filter_index)) continue;
            cui_push_id_int(ui, i);
            record_row(ui, &records->records[i], report->domain);
            cui_pop_id(ui);
        }
    }
}

static void record_section(cui_ctx *ui, app_state *app, const ui_text *text) {
    record_filter filter;
    build_record_filter(&app->report->records, text, &filter);
    cui_tabs(ui, "record-filter", filter.label_pointers, filter.count, &app->record_filter_index,
             .variant = CUI_TABS_PILL);
    record_table(ui, app->report, app->record_filter_index, text);
}

/* ------------------------------------------------------------------------ */
/* Page                                                                     */
/* ------------------------------------------------------------------------ */

/* Says where the answers came from, since a cache can lag behind a change. */
static void source_note(cui_ctx *ui, const lookup_report *report, const ui_text *text) {
    char note[DNS_DOMAIN_CAPACITY + 128];
    if (!report->asks_name_server_directly) {
        cui_muted(ui, text->strings.source_resolver);
        return;
    }
    snprintf(note, sizeof note, text->formats.source_direct, report->name_server.host_name);
    cui_muted(ui, note);
}

static bool has_problem(const lookup_report *report) {
    return report->status != DNS_STATUS_OK || report->failed_queries[0] != '\0';
}

/* The domain's status first ("does not exist"), then the queries that got no answer. */
static void report_problem(cui_ctx *ui, const lookup_report *report, const ui_text *text) {
    char description[SCAN_PROBLEM_CAPACITY + 256], failed[SCAN_PROBLEM_CAPACITY + 64] = "";
    if (report->failed_queries[0]) snprintf(failed, sizeof failed, text->formats.failed_queries, report->failed_queries);
    const char *status = ui_dns_status_message(text, report->status);
    snprintf(description, sizeof description, "%s%s%s", status, status[0] && failed[0] ? " " : "", failed);

    bool found_some_records = report->records.count > 0;
    cui_alert(ui, found_some_records ? text->strings.some_queries_failed : text->strings.no_records_found,
              .description = description, .tone = found_some_records ? CUI_TONE_WARNING : CUI_TONE_DANGER);
}

void records_page(cui_ctx *ui, app_state *app) {
    const ui_text *text = app_text(app);
    if (lookup_task_is_running(&app->lookup)) {
        waiting_state(ui, text);
        return;
    }
    if (!app->report) {
        cui_empty_state(ui, text->strings.no_lookup_title, .icon = CUI_ICON_GLOBE,
                        .description = text->strings.no_lookup_description);
        return;
    }

    cui_heading(ui, app->report->domain, 4);
    source_note(ui, app->report, text);
    if (has_problem(app->report)) report_problem(ui, app->report, text);
    if (app->report->records.count == 0) return;
    mail_summary(ui, &app->report->mail, text);
    record_section(ui, app, text);
}
